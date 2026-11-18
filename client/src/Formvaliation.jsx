export const MAX_URL_LENGTH = 2048;
const MAX_EMAIL_LENGTH = 254;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/**
 * Light, UX-only check on the URL field.
 *
 * Deliberately does NOT try to parse the URL or require a scheme: analysts often
 * paste defanged links (hxxps://evil[.]com) or scheme-less ones (bit.ly/abc), and
 * decoding/normalising those is the server's job (FR II). The server is the single
 * authority on what counts as a valid URL (FR XI); this only catches obvious slips.
 */
export function validateUrlInput(rawValue) {
  const value = rawValue.trim();
  if (!value) return { error: "Please enter a URL." };
  if (/\s/.test(value)) return { error: "A URL can't contain spaces." };
  if (value.length > MAX_URL_LENGTH) {
    return { error: `That URL is too long (maximum ${MAX_URL_LENGTH} characters).` };
  }
  return { value };
}

/** The alert email is optional (FR IX / NFR III): blank is valid, junk is not. */
export function validateOptionalEmail(rawValue) {
  const value = rawValue.trim();
  if (!value) return { value: "" };
  if (value.length > MAX_EMAIL_LENGTH || !EMAIL_PATTERN.test(value)) {
    return { error: "Enter a valid email address, or leave this blank." };
  }
  return { value };
}