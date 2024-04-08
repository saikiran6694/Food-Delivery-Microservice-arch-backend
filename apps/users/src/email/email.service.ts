import { MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';

type mailOptions = {
  subject: string;
  email: string;
  name: string;
  activationCode: any;
  template: string;
};

@Injectable()
export class EmailService {
  constructor(private mailService: MailerService) {}

  async sendMail({
    subject,
    email,
    name,
    template,
    activationCode,
  }: mailOptions) {
    await this.mailService.sendMail({
      to: email,
      subject,
      template,
      context: {
        name,
        activationCode,
      },
    });
  }
}
