# ThreatLens Testing & Validation Plan

## Phase 1: Production Readiness Testing

### Step 1: Environment Validation
**Goal**: Ensure the development environment is properly configured

**Actions**:
```bash
# Run environment check
python check_environment.py
```

**Expected Results**:
- ✅ Python 3.8+ installed
- ✅ All required dependencies installed
- ✅ .env file configured with API keys
- ✅ All critical files present
- ✅ Directory structure correct

**Common Issues & Fixes**:
- Missing dependencies: `pip install -r requirements.txt`
- Missing .env: `cp .env.example .env` and configure API keys
- Missing Node.js: Install Node.js and run `cd frontend && npm install`

### Step 2: System Validation
**Goal**: Test all core components end-to-end

**Actions**:
```bash
# Run comprehensive system validation
python test_system_validation.py
```

**Test Coverage**:
1. **Environment Setup** - File structure, dependencies, configuration
2. **API Health** - Basic health checks, database connectivity, LLM config
3. **Repository Validation** - GitHub repo validation, error handling
4. **Database Operations** - Health, statistics, integrity
5. **Analysis Workflow** - Queue status, routing logic
6. **Error Handling** - 404s, validation errors, exception handling
7. **Configuration Management** - Config validation, summary

**Expected Results**:
- All tests pass (100% success rate)
- Server starts and responds correctly
- Database is healthy and accessible
- Configuration is valid
- Error handling works properly

### Step 3: Manual Testing Checklist

#### Backend API Testing
- [ ] Server starts without errors: `python run_server.py`
- [ ] Health endpoint responds: `curl http://localhost:8000/health`
- [ ] API docs accessible: http://localhost:8000/docs
- [ ] Repository validation works: Test with valid/invalid GitHub URLs
- [ ] Database operations functional: Check `/database/health`
- [ ] Configuration endpoints work: Check `/config/summary`

#### Frontend Testing (if applicable)
- [ ] Frontend builds: `cd frontend && npm run build`
- [ ] Frontend serves: `cd frontend && npm run dev`
- [ ] UI loads without errors
- [ ] API integration works
- [ ] Error states display properly

#### Integration Testing
- [ ] Full repository analysis workflow
- [ ] PR analysis workflow
- [ ] RAG search functionality
- [ ] Knowledge base operations

## Phase 2: Critical Bug Fixes

### Common Issues to Watch For

1. **Environment Issues**
   - Missing API keys
   - Incorrect Python version
   - Missing dependencies
   - File permission issues

2. **Database Issues**
   - Migration failures
   - Connection errors
   - Schema inconsistencies
   - Data corruption

3. **API Issues**
   - Endpoint failures
   - Request validation errors
   - Response format issues
   - Timeout problems

4. **Integration Issues**
   - LLM API failures
   - GitHub API rate limits
   - Vector search errors
   - File processing issues

### Bug Fix Process

1. **Identify**: Run validation scripts to identify issues
2. **Isolate**: Use individual component tests to isolate problems
3. **Fix**: Implement targeted fixes
4. **Validate**: Re-run tests to confirm fixes
5. **Document**: Update documentation if needed

## Phase 3: Error Handling Improvements

### Current Error Handling Status
✅ **Already Implemented**:
- Comprehensive exception handlers for all error types
- Request ID tracking for debugging
- Proper HTTP status codes
- Detailed error messages in debug mode
- Repository-specific error handling
- Validation error handling
- Timeout and resource error handling

### Potential Improvements
- [ ] Add retry logic for transient failures
- [ ] Implement circuit breaker pattern for external APIs
- [ ] Add more detailed error context
- [ ] Improve user-friendly error messages
- [ ] Add error recovery suggestions

## Testing Commands Quick Reference

```bash
# Environment check
python check_environment.py

# Full system validation
python test_system_validation.py

# Start server for manual testing
python run_server.py

# Test specific endpoints
curl http://localhost:8000/health
curl http://localhost:8000/resources
curl -X POST http://localhost:8000/validate_repo -H "Content-Type: application/json" -d '{"repo_url": "https://github.com/octocat/Hello-World.git"}'

# Frontend testing
cd frontend
npm install
npm run build
npm run dev
```

## Success Criteria

### Phase 1 Complete When:
- [ ] Environment check passes 100%
- [ ] System validation passes 100%
- [ ] Manual testing checklist completed
- [ ] No critical bugs identified
- [ ] All core workflows functional

### Ready for Phase 2 When:
- [ ] All identified bugs documented
- [ ] Fix priority assigned
- [ ] Implementation plan created

### Ready for Production When:
- [ ] All tests pass consistently
- [ ] Error handling robust
- [ ] Performance acceptable
- [ ] Documentation complete
- [ ] User experience smooth

## Next Steps After Testing

1. **If tests pass**: Move to UX improvements and real repository testing
2. **If tests fail**: Fix critical issues and re-test
3. **If partial success**: Prioritize fixes and implement incrementally

## Monitoring & Maintenance

- Set up regular testing schedule
- Monitor error rates and performance
- Update tests as features evolve
- Maintain test documentation