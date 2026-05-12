import { Elysia, t } from "elysia";
import { cors } from "@elysia/cors";
import { sql } from "./db";
import { staticPlugin } from "@elysia/static";
import { sign, verify } from "./lib/jwt.js";

const privKeyRaw = process.env.JWT_PRIVATE_KEY;
const pubKeyRaw = process.env.JWT_PUBLIC_KEY;
const privKey = privKeyRaw ? privKeyRaw.replace(/\\n/g, "\n") : null;
const pubKey = pubKeyRaw ? pubKeyRaw.replace(/\\n/g, "\n") : null;

const app = new Elysia()
  .use(cors())
  .use(
    staticPlugin({
      assets: "../../client",
      prefix: "/",
    }),
  )
  .get("/", () => Bun.file("../../client/index.html"))

  .post(
    "/login",
    async ({ body, set }: { body: any; set: any }) => {
      const { email, password } = body;

      try {
        const users = await sql`
          SELECT id, email, password, publickey, encrypted_pk, salt, iv, mac
          FROM users WHERE email = ${email}`;
        if (users.length === 0) {
          set.status = 401;
          return { success: false, error: "login" };
        }
        const user = users[0];

        const isPasswordValid = await Bun.password.verify(
          password,
          user.password,
        );

        if (!isPasswordValid) {
          set.status = 401;
          return { success: false, error: "gagal login" };
        }

        const token = sign(
          { alg: "ES256", typ: "JWT" },
          {
            iss: "ITB-Chat-Server",
            sub: user.email,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
          },
          { role: "user" },
          privKey,
        );
        return {
          success: true,
          token: token,
          user: {
            id: user.id,
            email: user.email,
            publicKey: user.publickey,
            encryptedPrivateKey: user.encrypted_pk,
            salt: user.salt,
            iv: user.iv,
            mac: user.mac,
          },
        };
      } catch (error: any) {
        set.status = 500;
        return { success: false, error: error.message };
      }
    },
    {
      body: t.Object({
        email: t.String(),
        password: t.String(),
      }),
    },
  )

  .post(
    "/register",
    async ({ body, set }: { body: any; set: any }) => {
      const { email, password, publickey, privatekey, salt, iv, mac } = body;
      const hashedPassword = await Bun.password.hash(password);

      try {
        await sql`
          INSERT INTO users (email, password, publickey, encrypted_pk, salt, iv, mac)
          VALUES (${email}, ${hashedPassword}, ${publickey}, ${privatekey}, ${salt}, ${iv}, ${mac})
        `;
        return { success: true, message: "User created" };
      } catch (error: any) {
        set.status = 500;
        if (error.code === "23505") {
          return { success: false, error: "email already exists" };
        }
        return { success: false, error: error.message };
      }
    },
    {
      body: t.Object({
        email: t.String(),
        password: t.String(),
        publickey: t.String(),
        privatekey: t.String(),
        salt: t.String(),
        iv: t.String(),
        mac: t.String(),
      }),
    },
  )

  .post("/get-contacts", async ({ headers, set }) => {
    const authHeader = headers["authorization"];

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      set.status = 401;
      return { success: false, message: "Missing or invalid token" };
    }

    const token = authHeader.split(" ")[1];

    try {
      const decoded = verify(token, pubKey, {
        iss: "ITB-Chat-Server",
        algs: ["ES256"],
      });
      const userEmail = decoded.payload.sub;
      const currentUser = await sql`
              SELECT id FROM users WHERE email = ${userEmail}
          `;
      if (currentUser.length === 0) {
        set.status = 404;
        return { success: false, message: "User not found" };
      }

      const myId = currentUser[0].id;
      const contacts = await sql`
              SELECT id, email, publickey
              FROM users
              WHERE id != ${myId}
          `;

      return {
        success: true,
        contacts: contacts,
      };
    } catch (error: any) {
      console.error("JWT/DB Error:", error.message);
      set.status = 401;
      return { success: false, message: "Unauthorized: " + error.message };
    }
  })

  .post(
    "/send-message",
    async ({ body, headers, set }) => {
      const authHeader = headers["authorization"];
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        set.status = 401;
        return { success: false, error: "Unauthorized" };
      }

      const token = authHeader.split(" ")[1];

      try {
        const decoded = verify(token, pubKey, {
          iss: "ITB-Chat-Server",
          algs: ["ES256"],
        });
        const senderEmail = decoded.payload.sub;
        const { to, iv, ciphertext, mac } = body;
        await sql`
              INSERT INTO messages (sender_email, recipient_email, iv, ciphertext, mac)
              VALUES (${senderEmail}, ${to}, ${iv}, ${ciphertext}, ${mac})
          `;

        return { success: true, message: "Message delivered to server" };
      } catch (error: any) {
        console.error("Backend Error:", error.message);
        set.status = 401;
        return { success: false, error: "Invalid token or server error" };
      }
    },
    {
      body: t.Object({
        to: t.String(),
        iv: t.String(),
        ciphertext: t.String(),
        mac: t.String(),
      }),
    },
  )

  .post(
    "/get-messages",
    async ({ body, headers, set }) => {
      const authHeader = headers["authorization"];
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        set.status = 401;
        return { success: false, error: "Unauthorized" };
      }
      const token = authHeader.split(" ")[1];
      try {
        const decoded = verify(token, pubKey, {
          iss: "ITB-Chat-Server",
          algs: ["ES256"],
        });
        const myEmail = decoded.payload.sub;
        const { with: contactEmail } = body;
        const messages = await sql`
            SELECT sender_email AS "from", iv, ciphertext, mac, created_at
            FROM messages
            WHERE
                (sender_email = ${myEmail} AND recipient_email = ${contactEmail})
                OR
                (sender_email = ${contactEmail} AND recipient_email = ${myEmail})
            ORDER BY created_at ASC
        `;
        return { success: true, messages };
      } catch (error: any) {
        console.error("Fetch Error:", error.message);
        set.status = 401;
        return { success: false, error: "Invalid token or server error" };
      }
    },
    {
      body: t.Object({
        with: t.String(),
      }),
    },
  )

  .listen(3000);

console.log(
  `🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`,
);
