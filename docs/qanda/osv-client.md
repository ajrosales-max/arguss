Why is the OSV client separate from the vulnerability lens?
(Hint: separation of concerns — client knows about HTTP and OSV's API; lens knows about scoring and Findings. Each can be tested in isolation. If OSV ever changes its API, only the client changes.)
Why are batch queries cached separately from individual records?
(Hint: different cache lifetimes. Batch results are queries against a specific dep set; records are stable identifiers. Caching them together would waste cache space or invalidate too aggressively.)
Why does query_batch dedupe by (ecosystem, name, version) before querying?
(Hint: same package can appear at multiple paths in a transitive tree. The lockfile lists lodash once per installation location, but they're all the same package as far as OSV is concerned.)
What happens if OSV is down?
(Hint: OsvError raised. The vulnerability lens catches it and returns an empty LensScore so the scan can continue with other lenses.)
How does the client handle a malformed OSV response?
(Hint: today, it doesn't — JSON parse failure would propagate as an exception. Acceptable for capstone scope; future work would add response schema validation.)
