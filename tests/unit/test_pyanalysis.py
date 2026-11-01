import textwrap

import pytest

from prrisk.pyanalysis import (
    ChangeKind,
    RepoIndex,
    changed_functions,
    cyclomatic_complexity,
    functions,
    module_name,
)

SRC = textwrap.dedent(
    """\
    import os

    def simple(a):
        return a

    def branchy(x, y=1) -> int:
        if x and y or x:
            for i in range(x):
                if i % 2:
                    continue
        return 0

    class Cart:
        @staticmethod
        def total(items):
            return sum(items)

        def outer(self):
            def inner():
                return 1
            return inner()
    """
)


def test_extracts_functions_methods_and_nested_with_ranges():
    funcs = functions(SRC, "shop/cart.py")
    assert set(funcs) == {"simple", "branchy", "Cart.total", "Cart.outer", "Cart.outer.inner"}
    assert funcs["Cart.total"].start == 14  # decorator line counts as part of the function
    assert funcs["branchy"].signature == "(x, y=1) -> int"
    assert not funcs["simple"].is_test and funcs["Cart.outer"].is_public


def test_cyclomatic_complexity_counts_branches_and_boolean_operands():
    import ast

    tree = ast.parse(SRC)
    branchy = next(n for n in tree.body if getattr(n, "name", "") == "branchy")
    # 1 + if + (and: 1) + (or: 1) + for + inner if = 6
    assert cyclomatic_complexity(branchy) == 6
    assert functions(SRC, "x.py")["simple"].complexity == 1


def test_changed_lines_map_to_innermost_function():
    new = SRC.replace("return 1", "return 2")
    changes = changed_functions("shop/cart.py", SRC, new, added={20}, removed={20})
    assert [(c.qualname, c.kind) for c in changes] == [("Cart.outer.inner", ChangeKind.MODIFIED)]


def test_added_deleted_and_signature_changes():
    old = "def keep(a):\n    return a\n\ndef gone():\n    pass\n"
    new = "def keep(a, b):\n    return a + b\n\ndef fresh():\n    pass\n"
    changes = {
        c.qualname: c for c in changed_functions("m.py", old, new, {1, 2, 4, 5}, {1, 2, 4, 5})
    }
    assert changes["keep"].kind is ChangeKind.MODIFIED and changes["keep"].signature_changed
    assert changes["gone"].kind is ChangeKind.DELETED
    assert changes["fresh"].kind is ChangeKind.ADDED and changes["fresh"].complexity_delta == 1


def test_module_level_changes_touch_no_function():
    assert changed_functions("m.py", "X = 1\n", "X = 2\n", {1}, {1}) == []


def test_new_and_deleted_files():
    assert [
        c.kind for c in changed_functions("m.py", None, "def f():\n    pass\n", {1, 2}, set())
    ] == [ChangeKind.ADDED]
    assert [
        c.kind for c in changed_functions("m.py", "def f():\n    pass\n", None, set(), {1, 2})
    ] == [ChangeKind.DELETED]


def test_test_functions_are_marked():
    funcs = functions("def test_a():\n    pass\n\ndef helper():\n    pass\n", "tests/test_x.py")
    assert funcs["test_a"].is_test and not funcs["helper"].is_test


@pytest.mark.parametrize(
    ("path", "mod"),
    [
        ("src/shop/cart.py", "shop.cart"),
        ("shop/__init__.py", "shop"),
        ("a.py", "a"),
        ("README", "README"),
    ],
)
def test_module_name(path, mod):
    assert module_name(path) == mod


def test_repo_index_dependents_callers_and_tests():
    files = {
        "shop/cart.py": "def total(x):\n    return x\n",
        "shop/api.py": "from shop.cart import total\n\ndef handler():\n    return total(1)\n",
        "shop/report.py": "import shop.cart\n\nshop.cart.total(2)\n",
        "tests/test_cart.py": "from shop.cart import total\n\ndef test_t():\n    assert total(1)\n",
        "broken.py": "def (:\n",
    }
    index = RepoIndex.build(files)
    assert index.dependents_of_module("shop/cart.py") == {
        "shop.api",
        "shop.report",
        "tests.test_cart",
    }
    assert index.call_sites("total", exclude="shop/cart.py") == {
        "shop/api.py",
        "shop/report.py",
        "tests/test_cart.py",
    }
    assert index.tests_mentioning("total") == {"tests/test_cart.py"}
    assert index.tests_mentioning("nothing") == set()
    assert index.unparsable == ["broken.py"]
