import { ObjectType, Field } from '@nestjs/graphql';
import { User } from '../entities/user.entity';

@ObjectType()
export class Errortype {
  @Field()
  message: string;

  @Field({ nullable: true })
  code?: string;
}

@ObjectType()
export class RegisterResponse {
  @Field()
  activation_token: string;

  @Field(() => Errortype, { nullable: true })
  error?: Errortype;
}

@ObjectType()
export class ActivationResponse {
  @Field(() => User)
  user: User | any;

  @Field(() => Errortype, { nullable: true })
  error?: Errortype;
}

@ObjectType()
export class LoginResponse {
  @Field(() => User, { nullable: true })
  user?: User | any;

  @Field({ nullable: true })
  accessToken?: string;

  @Field({ nullable: true })
  refreshToken?: string;

  @Field(() => Errortype, { nullable: true })
  error?: Errortype;
}

@ObjectType()
export class LogoutResposne {
  @Field()
  message?: string;
}

@ObjectType()
export class ForgotPasswordResponse {
  @Field()
  message: string;

  @Field(() => Errortype, { nullable: true })
  error?: Errortype;
}

@ObjectType()
export class ResetPasswordResponse {
  @Field(() => User)
  user: User | any;

  @Field(() => Errortype, { nullable: true })
  error?: Errortype;
}
