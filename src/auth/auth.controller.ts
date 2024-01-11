import { Controller, Get, Post, Body, Patch, Param, Delete, UseGuards, Request } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginResponse } from './interfaces/login-response.model';
import { UserResponse } from './interfaces/user-response.model';
import { RegisterUserDto, LoginDto, UpdateAuthDto, CreateUserDto } from './dto';
import { AuthGuard } from './guards/auth.guard';
import { User } from './entities/user.entity';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post()
  create(@Body() createUserDto: CreateUserDto): Promise<UserResponse> {
    return this.authService.create(createUserDto);
  }

  @Post('/login')
  login(@Body() loginDto: LoginDto): Promise<LoginResponse>{
    return this.authService.login(loginDto);
  }

  @Post('/register')
  register(@Body() registerUserDto: RegisterUserDto): Promise<LoginResponse>{
    console.log(registerUserDto);
    return this.authService.register(registerUserDto);
  }

  @UseGuards(AuthGuard)
  @Get('check-token')
  checkToken(@Request() req: Request): LoginResponse{
    const user = req['user'] as User;
    console.log(user);
    return{
      user,
      token: this.authService.getJwtToken({id: user._id})
    }
  }

  @UseGuards(AuthGuard)
  @Get()
  findAll():Promise<UserResponse[]> {
    return this.authService.findAll();
  }

  @UseGuards(AuthGuard)
  @Get(':id')
  findOne(@Param('id') id: string):Promise<UserResponse> {
    return this.authService.findOne(id);
  }


  @UseGuards(AuthGuard)
  @Patch(':id')
  update(@Param('id') id: string, @Body() updateUserDto: UpdateAuthDto) {
    return this.authService.update(+id, updateUserDto);
  }


  @UseGuards(AuthGuard)
  @Delete(':id')
  remove(@Param('id') id: string) {
    return this.authService.remove(+id);
  }
}
