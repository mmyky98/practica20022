<?php

namespace App\Http\Controllers;

use App\Models\User;
use Exception;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Response;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Validator;
use Illuminate\Support\Facades\Password;
use Illuminate\Auth\Events\PasswordReset;
use Illuminate\Validation\Rules\Password as RulesPassword;

/**
 *
 */
class UserController extends ApiController
{
    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function login(Request $request): JsonResponse
    {
        try {
            $validator = Validator::make($request->all(), [
                'email' => 'required|email',
                'password' => 'required'
            ]);

            if ($validator->fails()) {
                return $this->sendError('Bad request!', $validator->messages()->toArray());
            }

            $error = false;

            /** @var User $user */
            $user = User::where('email', $request->get('email'))->first();
            if (!$user) {
                $error = true;
            } else {
                if (!Hash::check($request->get('password'), $user->password)) {
                    $error = true;
                }
            }

            if ($error) {
                return $this->sendError('Bad credentials!');
            }

            $token = $user->createToken('Practica');

            return $this->sendResponse([
                'token' => $token->plainTextToken,
                'user' => $user->toArray()
            ]);
        } catch (Exception $exception) {
            Log::error($exception);

            return $this->sendError('Something went wrong, please contact administrator!', [], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     *
     */
    public function register(Request $request): JsonResponse
    {
        try {
            $validator = Validator::make($request->all(), [
                'name' => 'required',
                'email' => 'required|email|unique:users,email',
                'password' => 'required|confirmed'
            ]);

            if ($validator->fails()) {
                return $this->sendError('Bad request!', $validator->messages()->toArray());
            }

            $user = new User();
            $user->name = $request->get('name');
            $user->email = $request->get('email');
            $user->password = Hash::make($request->get('password'));
            $user->email_verified_at = Carbon::now();
            $user->save();

            $token = $user->createToken('Practica');

            return $this->sendResponse([
                'token' => $token->plainTextToken,
                'user' => $user->toArray()
            ]);
        } catch (Exception $exception) {
            Log::error($exception);

            return $this->sendError('Something went wrong, please contact administrator!', [], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }


    public function forgotPassword(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
        ]);

        $status = User::sendResetLink(
            $request->only('email')
        );

        if ($status == User::RESET_LINK_SENT) {
            return [
                'status' => __($status)
            ];
        }

        throw ValidationException::withMessages([
            'email' => [trans($status)],
        ]);
    }

    public function reset(Request $request)
    {
        $request->validate([
            'token' => 'required',
            'email' => 'required|email',
            'password' => ['required', 'confirmed', RulesPassword::defaults()],
        ]);

        $status = User::reset(
            $request->only('email', 'password', 'password_confirmation', 'token'),
            function ($user) use ($request) {
                $user->forceFill([
                    'password' => Hash::make($request->password),
                    'remember_token' => Str::random(60),
                ])->save();

                $user->tokens()->delete();

                event(new PasswordReset($user));
            }
        );

        if ($status == User::PASSWORD_RESET) {
            return response([
                'message'=> 'Password reset successfully'
            ]);
        }

        return response([
            'message'=> __($status)
        ], 500);

    }
}
