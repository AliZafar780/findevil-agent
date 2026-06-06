"""Wrapper to run test_server.py directly as a script using the venv."""
import sys
sys.path.insert(0, '.')
from tests.test_server import TestMCPServer
import asyncio

async def run_all():
    t = TestMCPServer()
    tests = [
        ("partition_scan", t.test_partition_scan),
        ("filesystem_info", t.test_filesystem_info),
        ("list_files", t.test_list_files),
        ("file_metadata", t.test_file_metadata),
        ("extract_file", t.test_extract_file),
        ("verify_hash", t.test_verify_hash),
        ("evidence_listing", t.test_evidence_listing),
        ("security_path_validation", t.test_security_path_validation),
        ("filesystem_no_offset", t.test_filesystem_success_without_offset),
        ("security_null_byte", t.test_security_null_byte),
        ("security_missing_required", t.test_security_missing_required),
    ]
    passed = 0
    failed = 0
    results = []
    for name, test_func in tests:
        try:
            await test_func()
            print(f"  ✅ {name}")
            passed += 1
            results.append((name, "PASS", ""))
        except Exception as e:
            print(f"  ❌ {name}: {e}")
            failed += 1
            results.append((name, "FAIL", str(e)[:200]))
    
    print(f"\n{'='*60}")
    print(f"RESULTS: {passed} passed, {failed} failed")
    print(f"{'='*60}")
    
    # Check evidence status
    from pathlib import Path
    test_img = "/evidence/cases/test.raw"
    has_evidence = Path(test_img).exists()
    print(f"\nEvidence file {test_img}: {'EXISTS' if has_evidence else 'NOT FOUND'}")
    if not has_evidence:
        print("NOTE: 7 of 11 tests skipped due to missing evidence (marked @skipif)")
    
    # Print summary of what failed due to env vs bugs
    print(f"\nDETAIL:")
    for name, status, err in results:
        if status == "FAIL":
            if "evidence" in err.lower():
                print(f"  {name}: ENV (missing evidence) - {err}")
            elif "timed out" in err.lower():
                print(f"  {name}: ENV (timeout) - {err}")
            else:
                print(f"  {name}: BUG? - {err}")

    return failed == 0

if __name__ == "__main__":
    success = asyncio.run(run_all())
    sys.exit(0 if success else 1)
