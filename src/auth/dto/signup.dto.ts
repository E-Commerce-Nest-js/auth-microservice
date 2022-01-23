import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class SignUpDto {
    @IsNotEmpty()
    @IsString()
    username: string;

    @IsNotEmpty()
    @IsEmail()
    @IsString()
    email: string;

    @IsNotEmpty()
    @IsString()
    password: string;
}
