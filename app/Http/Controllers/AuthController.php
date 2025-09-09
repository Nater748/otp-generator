<?php

namespace App\Http\Controllers;

use App\Mail\OtpMail;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Str;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        $request->validate([
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required|min:6',
        ]);

        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        // Generate OTP
        $otp = rand(100000, 999999);
        $user->otp = Hash::make($otp);
        $user->otp_expires_at = now()->addMinutes(10);
        $user->save();

        Mail::to($user->email)->send(new OtpMail($otp));

        return response()->json(['message' => 'User registered. OTP sent.'], 201);
    }

    // Verify OTP
    public function verifyOtp(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'otp' => 'required',
        ]);

        $user = User::where('email', $request->email)->first();

        if (! $user) {
            return response()->json(['message' => 'User not found.'], 404);
        }

        if (! $user->otp_expires_at || $user->otp_expires_at->isPast()) {
            return response()->json(['message' => 'OTP expired.'], 422);
        }

        if (! Hash::check($request->otp, $user->otp)) {
            return response()->json(['message' => 'Invalid OTP.'], 422);
        }

        $user->is_verified = true;
        $user->otp = null;
        $user->otp_expires_at = null;
        $user->api_token = Str::random(60);
        $user->save();

        return response()->json([
            'message' => 'Email verified.',
            'token' => $user->api_token,
        ]);
    }

    // Login
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        $user = User::where('email', $request->email)->first();

        if (! $user || ! Hash::check($request->password, $user->password)) {
            return response()->json(['message' => 'Invalid credentials'], 401);
        }

        if (! $user->is_verified) {
            return response()->json(['message' => 'Email not verified'], 403);
        }

        $user->api_token = Str::random(60);
        $user->save();

        return response()->json([
            'message' => 'Login successful',
            'token' => $user->api_token,
        ]);
    }

    // Protected route example
    public function profile(Request $request)
    {
        $token = $request->header('Authorization');

        $user = User::where('api_token', $token)->first();

        if (! $user) {
            return response()->json(['message' => 'Unauthorized'], 401);
        }

        return response()->json($user);
    }
}
