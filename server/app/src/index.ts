import { Elysia, t } from "elysia";
import { cors } from "@elysia/cors";
import { sql } from "./db";
import { staticPlugin } from "@elysia/static";
import { handleRegister } from "../../../client/js/main.js";

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
  .listen(3000);

console.log("Running");
