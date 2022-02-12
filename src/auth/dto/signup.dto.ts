import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class SignUpDto {
    @ApiProperty({
        description: 'Not unique username',
        example: 'username',
    })
    @IsNotEmpty()
    @IsString()
    username: string;

    @ApiProperty({
        example: 'user@mail.com',
    })
    @IsNotEmpty()
    @IsEmail()
    @IsString()
    email: string;

    @ApiProperty({
        example: 'password',
    })
    @IsNotEmpty()
    @IsString()
    password: string;
}
