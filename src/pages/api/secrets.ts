import type { NextApiRequest, NextApiResponse } from "next";
import * as jwt from "jsonwebtoken";
import * as yml from "js-yaml";
import * as fs from "fs";

type Data = {
  message: string;
};

type Config = {
  name: string;
  repository_url: string;
  content: {
    [key: string]: string;
  };
};
export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse<Data>
) {
  const { authorization } = req.headers;

  if (!authorization) {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  const [authType, token] = authorization.split(" ");

  if (authType !== "Bearer") {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }

  try {
    const secret = yml.load(
      fs.readFileSync("public/secrets/starboy_secrets.yml", "utf8")
    ) as Config;

    if (!secret) {
      res.status(500).json({ message: "Internal Error" });
      return;
    }

    const payload = jwt.verify(token, secret.content["jwt-secret"]);
    if (!payload) {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    if (payload.sub !== "starboy") {
      res.status(401).json({ message: "Unauthorized" });
      return;
    }

    const flag = process.env.FLAG || "NO FLAG, CONTACT ADMIN";

    res.status(200).json({ message: flag });
  } catch {
    res.status(401).json({ message: "Unauthorized" });
    return;
  }
}
