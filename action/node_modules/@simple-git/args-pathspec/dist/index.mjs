const t = /* @__PURE__ */ new WeakMap();
function c(...n) {
  const e = new String(n);
  return t.set(e, n), e;
}
function r(n) {
  return n instanceof String && t.has(n);
}
function o(n) {
  return t.get(n) ?? [];
}
export {
  r as isPathSpec,
  c as pathspec,
  o as toPaths
};
//# sourceMappingURL=index.mjs.map
