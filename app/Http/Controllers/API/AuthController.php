<?php

namespace App\Http\Controllers\API;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Tymon\JWTAuth\Facades\JWTAuth;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'phone_number' => 'required|string|max:20|unique:users',
            'company_name' => 'nullable|string|max:255',
            'number_of_employees' => 'nullable|integer',
            'profile_picture' => 'nullable|image|mimes:jpeg,png,jpg,gif,svg|max:2048',
            'role_id' => 'nullable|integer',
            'password' => 'required|string|min:6|confirmed',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        $profilePicturePath = null;
        if ($request->hasFile('profile_picture')) {
            $profilePicturePath = $request->file('profile_picture')->store('profile_pictures', 'public');
        }

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'phone_number' => $request->phone_number,
            'company_name' => $request->company_name,
            'number_of_employees' => $request->number_of_employees,
            'profile_picture' => $profilePicturePath,
            'role_id' => $request->role_id ?? 1, // Default to admin if not specified
            'password' => Hash::make($request->password),
        ]);

        $token = JWTAuth::fromUser($user);

        return response()->json([
            'message' => 'User registered successfully',
            'user' => $user,
            'token' => $token,
            'role_id' => $user->role_id,
        ], 201);
    }

    public function login(Request $request)
    {
        $credentials = $request->only('email', 'password');
        if (!$token = JWTAuth::attempt($credentials)) {
            // Try phone_number as username
            $credentials = ['phone_number' => $request->email, 'password' => $request->password];
            if (!$token = JWTAuth::attempt($credentials)) {
                return response()->json(['error' => 'Invalid credentials'], 401);
            }
        }
        $user = auth()->user();
        return response()->json([
            'message' => 'Login successful',
            'token' => $token,
            'role_id' => $user ? $user->role_id : null,
            'user' => $user,
        ]);
    }

    public function logout(Request $request)
    {
        try {
            JWTAuth::invalidate(JWTAuth::getToken());
            return response()->json(['message' => 'Successfully logged out']);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Failed to logout, please try again.'], 500);
        }
    }

    /**
     * Get all users with their role_id
     */
    public function getAllUsersWithRoleId()
    {
        try {
            $users = User::select('id', 'name', 'email', 'role_id', 'company_name', 'phone_number')->get();
            return response()->json([
                'users' => $users
            ]);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Failed to fetch users'], 500);
        }
    }

    /**
     * Get current user profile
     */
    public function getProfile()
    {
        try {
            $user = auth()->user();
            if (!$user) {
                return response()->json(['error' => 'User not authenticated'], 401);
            }
            
            return response()->json([
                'user' => $user
            ]);
        } catch (\Exception $e) {
            return response()->json(['error' => 'Failed to fetch profile'], 500);
        }
    }
}
