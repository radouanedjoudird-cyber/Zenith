import { Transform } from 'class-transformer';
import { IsEmail, IsNotEmpty, IsString, Matches, MaxLength, MinLength } from 'class-validator';

export class SigninDto {
  // SECURITY: Generic error message prevents "Email Enumeration" discovery
  @IsEmail({}, { message: 'Invalid email or password format.' })
  @IsNotEmpty()
  @MaxLength(100)
  @Transform(({ value }) => value?.trim().toLowerCase())
  email: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(10)
  @MaxLength(32)
  // SYMMETRY: Ensures allowed characters match the Signup policy to prevent lockouts
  @Matches(/^[A-Za-z\d@$!%*?&_#^()]*$/, {
    message: 'Invalid email or password format.',
  })
  password: string;
}