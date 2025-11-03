import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsOptional, IsString } from 'class-validator';
import { LoginDto } from './login.dto';

export class RegisterDto extends LoginDto {
  @ApiProperty({
    description: 'The name of the user',
    example: 'test',
  })
  @IsString()
  @IsNotEmpty()
  name: string;
}