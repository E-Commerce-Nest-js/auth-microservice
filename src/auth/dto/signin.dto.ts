import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class SignInDto {
    @ApiProperty({
        example: 'admin@mail.com',
    })
    @IsNotEmpty()
    @IsEmail()
    @IsString()
    email: string;

    @ApiProperty({
        example: 'admin',
    })
    @IsNotEmpty()
    @IsString()
    password: string;
}
