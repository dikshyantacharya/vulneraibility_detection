from vckg.selection.function_curriculum import select_function_curriculum_pairs


def row(id, project, files, func, label, patch="fix1"):
    return {
        "id": id,
        "project": project,
        "project_url": f"https://example.com/{project}",
        "filepath": f"src/{func}.c",
        "function": func,
        "label": label,
        "patch_commit": patch,
        "eligible_source_files": files,
    }


def test_selects_exact_smallest_pairs():
    samples = [
        row("big-v", "big", 100, "f1", "vulnerable"),
        row("small-v", "small", 2, "f1", "vulnerable"),
        row("mid-v", "mid", 10, "f1", "vulnerable"),
        row("big-f", "big", 100, "f1", "fixed"),
        row("small-f", "small", 2, "f1", "fixed"),
        row("mid-f", "mid", 10, "f1", "fixed"),
    ]

    selected = select_function_curriculum_pairs(samples, target_functions=2)
    ids = [s["id"] for s in selected]
    assert ids == ["small-v", "small-f", "mid-v", "mid-f"]


def test_allows_multiple_functions_from_same_small_project():
    samples = [
        row("a-v", "small", 2, "a", "vulnerable", "fix-a"),
        row("a-f", "small", 2, "a", "fixed", "fix-a"),
        row("b-v", "small", 2, "b", "vulnerable", "fix-b"),
        row("b-f", "small", 2, "b", "fixed", "fix-b"),
        row("c-v", "large", 50, "c", "vulnerable", "fix-c"),
        row("c-f", "large", 50, "c", "fixed", "fix-c"),
    ]
    selected = select_function_curriculum_pairs(samples, target_functions=2)
    ids = [s["id"] for s in selected]
    assert ids == ["a-v", "a-f", "b-v", "b-f"]
