import si from "systeminformation";
import bcrypt from "bcrypt";
import fs from "fs";
import crypto from "crypto-js";

export class License {
  endDate: number;
  startDate: number;
  secret: string;
  private defaultPath = "license";
  constructor({
    date,
    secret,
  }: {
    secret: string;
    date: { endDate: number; startDate: number };
  }) {
    this.endDate = date.endDate;
    this.startDate = date.startDate;
    this.secret = secret;
  }

  async generateLicense(path?: string) {
    const disks = await si.diskLayout();
    const salt = bcrypt.genSaltSync(10);
    const hashed = bcrypt.hashSync(disks[0].serialNum, salt);

    const startDate = crypto.AES.encrypt(
      this.startDate.toString(),
      this.secret
    );
    const endDate = crypto.AES.encrypt(this.endDate.toString(), this.secret);

    fs.writeFileSync(
      path || this.defaultPath,
      `${hashed}\n${startDate}\n${endDate}`
    );
    return hashed;
  }
  async checkLicense(path?: string) {
    try {
      const disks = await si.diskLayout();
      const readed = fs.readFileSync(path || this.defaultPath);
      const [license, startDate, endDate] = readed.toString().split("\n");

      const sDate = Number(
        crypto.AES.decrypt(startDate, this.secret).toString(crypto.enc.Utf8)
      );

      const eDate = Number(
        crypto.AES.decrypt(endDate, this.secret).toString(crypto.enc.Utf8)
      );

      const check = bcrypt.compareSync(disks[0].serialNum, license);

      return sDate < Date.now() && eDate > Date.now() && check;
    } catch (error: any) {
      console.log(error.message);
      return undefined;
    }
  }

  async readLicense(path?: string) {
    try {
      const readed = fs.readFileSync(path || this.defaultPath);
      const [code, start, end] = readed.toString().split("\n");
      return {
        valid: await this.checkLicense(path),
        code,
        start,
        end,
      };
    } catch (error) {}
  }
}
