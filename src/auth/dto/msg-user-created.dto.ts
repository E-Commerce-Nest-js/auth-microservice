import { IsEmail, IsMongoId, IsNotEmpty, IsString } from 'class-validator';

export class MsgUserCreatedDto {
    @IsNotEmpty()
    @IsString()
    @IsMongoId()
    userId: string;

    @IsNotEmpty()
    @IsEmail()
    @IsString()
    email: string;
}
