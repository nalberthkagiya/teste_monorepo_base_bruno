import { compare } from "bcryptjs";

// export async function saltAndHashPassword(plainPassword: string): Promise<string> {
//   const env = process.env.BCRYPT_SALT_ROUNDS;
//   const SALT_ROUNDS = env ? parseInt(env) : 10;
//   return await hash(plainPassword, SALT_ROUNDS);
// }

export async function comparePassword(plainPassword: string, password: string) {
  return compare(plainPassword, password);
}