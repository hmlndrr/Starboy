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
    res.status(401).json({ message: "No authorization header" });
    return;
  }

  const [authType, token] = authorization.split(" ");

  if (authType !== "Bearer") {
    res.status(401).json({ message: "Not A Valid Bearer" });
    return;
  }

  if (!token) {
    res.status(401).json({ message: "Not A Valid Token" });
    return;
  }

  try {
    const url = process.env.ME || "http://localhost:3000";
    const secret = yml.load(
      await fetch(`${url}/secrets/starboy_secrets.yml`).then((res) =>
        res.text()
      )
    ) as Config;

    if (!secret) {
      res.status(500).json({ message: "Internal Error, Contact Admin" });
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

    const flag = process.env.FLAG || "No Flag, Contact Admin";

    res.status(200).json({ message: flag });
  } catch (e: any) {
    console.log(e);
    res.status(500).json({ message: "An Error Just Happened, Contact Admin" });
    return;
  }
}
