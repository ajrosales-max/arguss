# Mini repository fixtures

Small directory trees with `package.json` and `.github/workflows/` for pipeline lens **test reality** checks.

| Directory | Scenario |
|-----------|----------|
| [`clean-with-tests/`](clean-with-tests/) | Valid test script and workflow runs tests |
| [`workflow-skips-tests/`](workflow-skips-tests/) | Workflow present but does not run tests |
| [`noop-test-script/`](noop-test-script/) | `npm test` is a no-op |
| [`no-test-script/`](no-test-script/) | Missing `test` script in package.json |
| [`no-test-files/`](no-test-files/) | No test files in repo |
| [`yarn-tests/`](yarn-tests/) | Yarn-oriented layout (edge case) |

Each contains `package.json`, optional `__tests__/`, and `.github/workflows/ci.yml` tailored to the scenario.
