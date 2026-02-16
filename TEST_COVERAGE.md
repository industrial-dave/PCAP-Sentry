# Test Coverage Improvement Plan

## Current Status

**Overall Coverage: 7%** (as of 2026-02-16)

| Module | Lines | Coverage | Priority |
|--------|-------|----------|----------|
| pcap_sentry_gui.py | 6,346 | 7% | Medium |
| threat_intelligence.py | 316 | 20% | High |
| update_checker.py | 342 | 11% | High |
| enhanced_ml_trainer.py | 184 | 0% | High |

## Why Coverage is Low

The current tests (21 tests total) focus on:
- Individual function validation
- Security testing (path traversal, input validation)
- Performance benchmarks
- Edge case handling

**Main Gap:** The GUI application (pcap_sentry_gui.py) has 6,346 lines and requires GUI automation to test properly.

## OpenSSF Recommendation

> "It is SUGGESTED that the test suite cover most (or ideally all) the code branches, input fields, and functionality."

This is a **SUGGESTED** criterion, not required for the passing badge. However, good coverage demonstrates:
- Code quality and maintainability
- Confidence in refactoring
- Early bug detection
- Documentation of expected behavior

## Coverage Targets

Based on project type:

- **Non-GUI modules** (threat_intelligence, update_checker, ml_trainer): **Target 60-80%**
  - Achievable with unit tests
  - Test all public functions and error paths
  
- **GUI application** (pcap_sentry_gui): **Target 30-40%**
  - GUI testing is complex and time-consuming
  - Focus on business logic, not UI event handlers
  - Use mocks for tkinter components

- **Overall project**: **Target 40-50%**
  - Realistic for GUI-heavy application
  - Demonstrates thorough testing of critical paths

## Improvement Strategy

### Phase 1: Low-Hanging Fruit (Target: 15-20% coverage)

**1. threat_intelligence.py (currently 21%)**
- Add tests for uncovered cache operations
- Test error handling in API calls
- Test configuration loading/validation
- Estimated: 10 new tests → 60% coverage

**2. update_checker.py (currently 12%)**
- Test version comparison logic
- Test update download scenarios
- Mock HTTP requests with various responses
- Test error handling (network failures, invalid versions)
- Estimated: 8 new tests → 50% coverage

**3. enhanced_ml_trainer.py (currently 0%)**
- Test model training with mock data
- Test feature extraction
- Test model loading/saving
- Mock scikit-learn components
- Estimated: 12 new tests → 60% coverage

**Phase 1 Total:** ~30 new tests, ~15-20% overall coverage

### Phase 2: GUI Business Logic (Target: 30-35% coverage)

**4. pcap_sentry_gui.py - Non-GUI Functions**
- Extract and test data processing logic
- Test file parsing without GUI
- Test analysis computations
- Mock tkinter widgets in tests
- Estimated: 20-30 tests → 15% GUI coverage

**Phase 2 Total:** ~50-60 tests total, ~30-35% overall coverage

### Phase 3: Integration Tests (Target: 40-50% coverage)

**5. End-to-End Workflows**
- Test complete PCAP analysis pipeline
- Test IOC extraction workflow
- Test report generation
- Use pytest fixtures for test data
- Estimated: 15-20 integration tests → 40-50% overall

## Implementation Priorities

### High Priority (Recommended)
✅ **threat_intelligence.py** - Core security module, testable without GUI
✅ **update_checker.py** - Critical for security updates
✅ **enhanced_ml_trainer.py** - Machine learning logic

### Medium Priority (Good to have)
- **pcap_sentry_gui.py** - Extract testable business logic
- Add mocks for GUI components
- Focus on analysis and processing functions

### Low Priority (Optional)
- Full GUI automation testing
- Visual regression testing
- Performance profiling integration

## Testing Best Practices

### Use Mocks Effectively

```python
from unittest.mock import Mock, patch, MagicMock

def test_update_check_with_mock():
    \"\"\"Test update checking without real network calls\"\"\"
    with patch('requests.get') as mock_get:
        mock_get.return_value.json.return_value = {
            'tag_name': 'v2026.02.16-01'
        }
        # Test update logic
```

### Use Fixtures for Test Data

```python
import pytest

@pytest.fixture
def sample_pcap_data():
    \"\"\"Provide sample PCAP data for tests\"\"\"
    return {
        'packets': [...],
        'metadata': {...}
    }

def test_pcap_analysis(sample_pcap_data):
    result = analyze_pcap(sample_pcap_data)
    assert result['iocs_found'] == 5
```

### Parametrize Tests

```python
@pytest.mark.parametrize("input,expected", [
    ("192.168.1.1", True),
    ("invalid", False),
    ("2001:db8::1", True),
])
def test_ip_validation(input, expected):
    assert is_valid_ip(input) == expected
```

## Running Coverage Reports

### Command Line

```bash
# Run all tests with coverage
pytest tests/

# Run specific module with coverage
pytest tests/ --cov=Python/threat_intelligence.py

# Generate HTML report
pytest tests/ --cov=Python --cov-report=html

# Show missing lines
pytest tests/ --cov=Python --cov-report=term-missing

# Set minimum coverage threshold (fail if below)
pytest tests/ --cov=Python --cov-fail-under=40
```

### View HTML Report

After running tests, open: `htmlcov/index.html`

This shows:
- Line-by-line coverage
- Branches taken/missed
- Functions never called
- Files with lowest coverage

## Coverage vs Quality Trade-offs

**Don't Chase 100% Coverage:**
- GUI event handlers are hard to test
- Some error paths are unreachable in practice
- Diminishing returns after 70-80%
- Focus on critical paths and business logic

**Prioritize:**
1. Security-critical code (input validation, authentication)
2. Business logic (data processing, analysis)
3. Public APIs (functions used by other modules)
4. Error handling (exception paths)
5. Edge cases (boundary conditions)

**Skip:**
- Simple getters/setters
- GUI layout code
- External library wrappers (test the wrapper, not the library)
- Defensive code that "can't happen"

## Timeline Estimate

- **Phase 1** (15-20% coverage): 2-3 days
- **Phase 2** (30-35% coverage): 3-4 days
- **Phase 3** (40-50% coverage): 4-5 days

**Total:** 1-2 weeks of focused testing work

## Current Achievement

✅ **Testing infrastructure ready:**
- pytest framework configured
- pytest-cov integrated
- 21 baseline tests (100% pass)
- Standard test invocation: `pytest tests/`
- HTML coverage reports enabled

✅ **OpenSSF Requirements:**
- Automated tests exist ✅
- Standard invocation method ✅
- Test policy documented ✅
- Coverage tracking enabled ✅

**Next Steps:** Implement Phase 1 to reach 15-20% coverage for OpenSSF Best Practices recommendation.

## Resources

- [pytest documentation](https://docs.pytest.org/)
- [pytest-cov documentation](https://pytest-cov.readthedocs.io/)
- [Python testing best practices](https://docs.python-guide.org/writing/tests/)
- [OpenSSF test coverage guidance](https://www.bestpractices.dev/en/criteria#test_policy)
