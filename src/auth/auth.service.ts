import { LoginDto } from './dto/login.dto';
import { BadRequestException, Injectable, InternalServerErrorException, Post, UnauthorizedException, Param } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import * as bcryptjs from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.model';
import { LoginResponse as LoginResponse } from './interfaces/login-response.model';
import { UserResponse } from './interfaces/user-response.model';
import { RegisterUserDto,UpdateAuthDto, CreateUserDto } from './dto';

@Injectable()
export class AuthService {
  
  constructor(@InjectModel(User.name) private userModel: Model<User>, private jwtSvc: JwtService){   
  }

  async create(createUserDto: CreateUserDto): Promise<UserResponse> {
    try{
      const newUser = new this.userModel({
        ...createUserDto,
        password: bcryptjs.hashSync(createUserDto.password, 10),
      })

      await newUser.save();

      const {password:_, ...user} = newUser.toJSON();
      
      return user;
    }catch(error){
      if(error.code === 11000){
        throw new BadRequestException(`${createUserDto.email} already exist!`)
      }
      throw new InternalServerErrorException('Something terrible happen!!!')
    }


  }

  async login(loginDto:LoginDto): Promise<LoginResponse>{
    const {email, password} = loginDto
    
    const user = await this.userModel.findOne({email});
    
    if(!user || !bcryptjs.compareSync(password, user.password)){
      throw new UnauthorizedException('Not valid credentials');
    }

    const {password:_, ...rest} = user.toJSON();
    return {
      user: rest,
      token: this.getJwtToken({
        id: user.id
      })
    }
  
  }

  async register(registerUserDto: RegisterUserDto): Promise<LoginResponse>{
    const userCreated = await this.create(registerUserDto);
    return {
      user: userCreated,
      token: this.getJwtToken({
        id: userCreated._id
      })
    }
  }

  findAll(): Promise<UserResponse[]> {
    return this.userModel.find();
  }

  async findById(id: string): Promise<UserResponse> {
    const user = await this.userModel.findById(id);
    const {password, ...rest} = user.toJSON();
    return rest;
  }


  async findOne(id: string): Promise<UserResponse> {
    const user = await this.userModel.findOne({ _id: id });
    if (!user) {
      throw new Error('User not found');
    }
    const { password, ...rest } = user.toJSON();
    return rest;
  }

  update(id: number, updateUserDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJwtToken(payload: JwtPayload): string{
    const token = this.jwtSvc.sign(payload);
    return token;
  }
}
