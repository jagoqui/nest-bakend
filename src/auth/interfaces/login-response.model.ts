import { UserResponse } from "./user-response.model";

export interface LoginResponse{
    user: UserResponse,
    token: string 
}