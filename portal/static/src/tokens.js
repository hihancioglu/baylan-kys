export function getToken(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(`--${name}`).trim();
}

export default { getToken };
