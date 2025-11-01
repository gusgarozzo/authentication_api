import { IsNotEmpty, IsOptional, IsString } from "class-validator";
import { LoginDto } from "./login.dto";

export class RegisterDto extends LoginDto{
  @IsString()
  @IsNotEmpty()
  name: string
}