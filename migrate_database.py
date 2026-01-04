#!/usr/bin/env python3
"""
Standalone Database Migration Script for Security Wiki Generator

This script can be run independently to migrate the database to the latest schema.
It includes all necessary migration logic and can be used for deployment automation.

Usage:
    python migrate_database.py                    # Apply all pending migrations
    python migrate_database.py --status           # Show migration status
    python migrate_database.py --validate         # Validate migrations
    python migrate_database.py --rollback N       # Rollback to version N
    python migrate_database.py --backup           # Create backup only
"""
import sys
import os
import argparse
import logging
from datetime import datetime
from pathlib import Path

# Add the api directory to the path so we can import modules
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'api'))

try:
    from migrations import MigrationManager
    from config import settings
except ImportError as e:
    print(f"Error importing required modules: {e}")
    print("Make sure you're running this script from the project root directory.")
    sys.exit(1)

def setup_logging(verbose=False):
    """Setup logging for migration script"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('migration.log')
        ]
    )

def show_status(manager):
    """Show migration status"""
    status = manager.get_migration_status()
    
    print("Database Migration Status")
    print("=" * 40)
    print(f"Current version: {status['current_version']}")
    print(f"Latest version:  {status['latest_version']}")
    print(f"Pending migrations: {status['pending_migrations']}")
    print(f"Up to date: {'Yes' if status['up_to_date'] else 'No'}")
    print()
    
    print("Migration History:")
    print("-" * 40)
    for migration in status['migrations']:
        status_icon = "[APPLIED]" if migration['applied'] else "[PENDING]"
        print(f"{status_icon} v{migration['version']}: {migration['description']}")
    
    return status['up_to_date']

def validate_migrations(manager):
    """Validate migration integrity"""
    validation = manager.validate_migrations()
    
    print("Migration Validation")
    print("=" * 40)
    print(f"Valid: {'Yes' if validation['valid'] else 'No'}")
    print(f"Migration count: {validation['migration_count']}")
    print(f"Current version: {validation['current_version']}")
    print()
    
    if validation['errors']:
        print("Errors:")
        for error in validation['errors']:
            print(f"  [ERROR] {error}")
        print()
    
    if validation['warnings']:
        print("Warnings:")
        for warning in validation['warnings']:
            print(f"  [WARNING] {warning}")
        print()
    
    return validation['valid']

def create_backup(manager):
    """Create database backup"""
    print("Creating database backup...")
    
    # Use DatabaseManager for backup functionality
    from database import DatabaseManager
    db_manager = DatabaseManager(manager.db_path)
    
    backup_info = db_manager.create_backup()
    
    if backup_info['success']:
        print(f"[SUCCESS] Backup created: {backup_info['backup_name']}")
        print(f"  Size: {backup_info.get('size_mb', 0):.1f} MB")
        return True
    else:
        print(f"[ERROR] Backup failed: {backup_info['error']}")
        return False

def apply_migrations(manager, create_backup_first=True):
    """Apply all pending migrations"""
    # Check current status
    status = manager.get_migration_status()
    
    if status['up_to_date']:
        print("[SUCCESS] Database is already up to date!")
        return True
    
    print(f"Found {status['pending_migrations']} pending migrations")
    
    # Validate migrations first
    if not validate_migrations(manager):
        print("[ERROR] Migration validation failed. Aborting.")
        return False
    
    # Create backup if requested
    if create_backup_first:
        if not create_backup(manager):
            print("[ERROR] Backup failed. Aborting migration for safety.")
            return False
    
    # Apply migrations
    print("\nApplying migrations...")
    result = manager.apply_migrations()
    
    if result['success']:
        print(f"[SUCCESS] Successfully applied {len(result['migrations_applied'])} migrations")
        for migration in result['migrations_applied']:
            print(f"  [APPLIED] v{migration['version']}: {migration['description']}")
        
        # Final validation
        final_status = manager.get_migration_status()
        if final_status['up_to_date']:
            print("\n[SUCCESS] Database migration completed successfully!")
            return True
        else:
            print("\n[WARNING] Migration completed but database is not fully up to date")
            return False
    else:
        print("[ERROR] Migration failed:")
        for error in result['errors']:
            print(f"  [ERROR] {error}")
        return False

def rollback_migrations(manager, target_version):
    """Rollback migrations to target version"""
    current_version = manager.get_current_version()
    
    if target_version >= current_version:
        print(f"[ERROR] Target version {target_version} is not lower than current version {current_version}")
        return False
    
    print(f"Rolling back from version {current_version} to {target_version}")
    
    # Create backup first
    if not create_backup(manager):
        print("[ERROR] Backup failed. Aborting rollback for safety.")
        return False
    
    # Perform rollback
    result = manager.rollback_migration(target_version)
    
    if result['success']:
        print(f"[SUCCESS] Successfully rolled back {len(result['migrations_rolled_back'])} migrations")
        for migration in result['migrations_rolled_back']:
            print(f"  [ROLLED_BACK] v{migration['version']}: {migration['description']}")
        return True
    else:
        print("[ERROR] Rollback failed:")
        for error in result['errors']:
            print(f"  [ERROR] {error}")
        return False

def main():
    """Main migration function"""
    parser = argparse.ArgumentParser(description='Database Migration Tool')
    parser.add_argument('--status', action='store_true', help='Show migration status')
    parser.add_argument('--validate', action='store_true', help='Validate migrations')
    parser.add_argument('--backup', action='store_true', help='Create backup only')
    parser.add_argument('--rollback', type=int, metavar='VERSION', help='Rollback to version')
    parser.add_argument('--no-backup', action='store_true', help='Skip backup creation')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose logging')
    
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    logger = logging.getLogger(__name__)
    
    print("Security Wiki Generator Database Migration Tool")
    print("=" * 50)
    
    try:
        # Initialize migration manager
        manager = MigrationManager()
        
        # Handle different commands
        if args.status:
            return 0 if show_status(manager) else 1
        
        elif args.validate:
            return 0 if validate_migrations(manager) else 1
        
        elif args.backup:
            return 0 if create_backup(manager) else 1
        
        elif args.rollback is not None:
            return 0 if rollback_migrations(manager, args.rollback) else 1
        
        else:
            # Default: apply migrations
            return 0 if apply_migrations(manager, not args.no_backup) else 1
        
    except Exception as e:
        logger.error(f"Migration script failed: {e}")
        print(f"[ERROR] Migration failed with error: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())