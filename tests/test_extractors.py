from vuln_commit_kg.kg.extractors.c_like import extract_functions_from_text


def test_extract_simple_function():
    code = "int f(int x) { if (x < 0) return -1; memcpy(a,b,x); return 0; }"
    funcs = extract_functions_from_text(code, "a.c")
    assert funcs
    assert funcs[0].name == "f"
