Worker test plan:
1. node --check src/index.js
2. Apply migrations to a disposable local D1 database.
3. Test admin and member login.
4. Test device lock and membership expiry.
5. Test stream source host allowlist.
6. Test HLS master playlist URI rewriting.
7. Test segment, audio, subtitle and encryption-key proxying.
8. Verify origin URLs never appear in client responses.
9. Test central broadcast start, stop and member visibility.
10. Do not deploy to production until all tests pass.
