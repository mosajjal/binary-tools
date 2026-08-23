"""Merged recipe registry consumed by gen_dockerfiles.py."""

from recipes_go import RECIPES as _GO
from recipes_rust import RECIPES as _RUST
from recipes_c import RECIPES as _C
from recipes_pt import RECIPES as _PT

RECIPES = {**_GO, **_RUST, **_C, **_PT}
