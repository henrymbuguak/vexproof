# ADR 0009: Call paths: a search proposes, the model reviews, the verifier checks

**Status:** accepted · **Date:** 2026-10-29

## Context
For an alert in a loaded module, the strongest evidence is a call path from the project's code
to the vulnerable function. Python has no static types to resolve calls exactly; a name-based
search finds absurd shortcuts (`Product.objects.filter()` "reaching" Pillow's `Image.filter`),
while a model asked to find a 20-step path alone is slow and can invent steps.

## Decision
- **Index** every loaded module: who calls, references or names what, with the receiver of each
  call classified from the code (`self`, `super()`, a variable built from a known class,
  `Class.method`, unknown). Classes are identified by full dotted names through the imports,
  including re-exports and star imports.
- **Certain vs possible hops.** A hop is certain when the code shows the identity of what is
  called; possible when a method is called on an object of unknown type. Method calls follow
  Python's method resolution order: `self.m()` in class K reaches the `m` K resolves to or a
  subclass override; `super().m()` the next definition above K; `Base.m(self)` exactly Base's.
- **Framework routes from declarations.** Some calls happen because of what project code
  declares, not what it calls: a model with an `ImageField` registered with a mounted admin
  site has its uploads validated by `forms.ImageField.to_python`, which opens them with Pillow
  (`django_admin_upload`). Found in project code, explained in the report, certain.
- **Search** (Dijkstra, backwards from the target): certain-only first; otherwise possible hops
  cost more the more functions share the name, and builtin method names (`split`, `format`)
  more still. Dispatch the code cannot show by name is a named rule: Pillow's `register_open`
  and `register_save` registries, and Django's `View.dispatch`, which calls the handler named
  after the HTTP verb on the same view object. Classes named in settings (`MIDDLEWARE`) reach
  their constructor (certain) and `__call__` (possible, reviewed).
- **Verify** every hop at its cited line, and carry types along the path: a view that builds a
  `CartAddProductForm` makes `self` a `CartAddProductForm` in the hops that follow. A failed
  verification blames the step that fixed the type, and the search tries again around it.
- **Review** with Muse Spark only when the best verified path has possible hops. The model can
  accept (explaining each possible hop), search again (`avoid` a wrong step, route `through` a
  known one), or read `callers` and `source`. It steers the search; it never adds a hop the
  verifier has not checked. Requests depend only on the target, so findings sharing a function
  share one review, and recordings replay.

## Limits
A path shows that each call is in the code, not that every condition on the way holds at run
time: `Image.new` calls `ImageColor.getcolor` only for string colours, and a path through it
still counts. This is the usual meaning of static reachability; the report shows every hop so a
reader can judge such conditions.

## Consequences
"Reachable" claims carry a path anyone can read, hop by hop, with uncertain hops marked and the
model's reason recorded. A lenient model could accept a wrong possible hop; the hop is visible
in the report, and the gold set (Chapter 6) will measure it. Absence of a path is never a clear.
