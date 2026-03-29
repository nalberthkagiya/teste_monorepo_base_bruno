export const isSafeRedirect = (url: string | null) => {
  return typeof url === "string" && /^\/(?!\/)/.test(url);
};

export const hasUppercase = (password: string) => /[A-Z]/.test(password);
export const hasLowercase = (password: string) => /[a-z]/.test(password);
export const hasNumber = (password: string) => /\d/.test(password);
export const hasMinLength = (password: string) => password.length >= 8;

export * from './zod'