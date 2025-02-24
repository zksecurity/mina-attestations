import { Bytes, Int64 } from 'o1js';
import { Schema } from '../../../src/index.ts';
import { z } from 'zod';

export { type Data, schema, CredentialData };

type Data = ReturnType<typeof schema.from>;

const Bytes16 = Bytes(16);

const schema = Schema({
  /**
   * Nationality of the owner.
   */
  nationality: Schema.String,

  /**
   * Full name of the owner.
   */
  name: Schema.String,

  /**
   * Date of birth of the owner.
   */
  birthDate: Int64,

  /**
   * Owner ID (16 bytes).
   */
  id: Bytes16,

  /**
   * Timestamp when the credential expires.
   */
  expiresAt: Schema.Number,
});

// zod validation

const UserData = z
  .object({
    name: z.string(),
    nationality: z.string(),
    birthDate: z.number(),
  })
  .strict();

const CredentialData = z.object({ owner: z.string(), data: UserData }).strict();
