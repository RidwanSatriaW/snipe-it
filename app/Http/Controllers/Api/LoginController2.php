<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Foundation\Auth\ThrottlesLogins;

class LoginController extends Controller
{
//     public function login(Request $request)
//     {
//         $validator = Validator::make($request->all(), [
//             'email' => 'required|email',
//             'password' => 'required'
//         ]);
//         $user = null;



//         if ($validator->fails()) {
//             return response()->json($validator->errors(), 400);
//         }

//         $user = User::where('email', $request->email)->first();

//         if (!$user || !Hash::check($request->password, $user->password)) {
//             return response()->json([
//                 'success' => false,
//                 'message' => 'Login Failed!',
//             ]);
//         }    

//         return response()->json([
//             'success' => true,
//             'message' => 'Login Success!',
//             'data'    => $user,
//             'token'   => $user->createToken('authToken')->accessToken    
//         ]);
//     // }

//    }
use ThrottlesLogins;
public function login(Request $request)
    {

        //If the environment is set to ALWAYS require SAML, return access denied
        if (config('app.require_saml')) {
            \Log::debug('require SAML is enabled in the .env - return a 403');
            return view('errors.403');
        }

        if (Setting::getSettings()->login_common_disabled == '1') {
            \Log::debug('login_common_disabled is set to 1 - return a 403');
            return view('errors.403');
        }

        $validator = $this->validator($request->all());

        if ($validator->fails()) {
            return redirect()->back()->withInput()->withErrors($validator);
        }

        $this->maxLoginAttempts = config('auth.passwords.users.throttle.max_attempts');
        $this->lockoutTime = config('auth.passwords.users.throttle.lockout_duration');

        if ($lockedOut = $this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);

            return $this->sendLockoutResponse($request);
        }

        $user = null;

        // Should we even check for LDAP users?
        if (Setting::getSettings()->ldap_enabled) { // avoid hitting the $this->ldap
            LOG::debug('LDAP is enabled.');
            try {
                LOG::debug('Attempting to log user in by LDAP authentication.');
                $user = $this->loginViaLdap($request);
                Auth::login($user, $request->input('remember'));

                // If the user was unable to login via LDAP, log the error and let them fall through to
            // local authentication.
            } catch (\Exception $e) {
                Log::debug('There was an error authenticating the LDAP user: '.$e->getMessage());
            }
        }

        // If the user wasn't authenticated via LDAP, skip to local auth
        if (! $user) {
            Log::debug('Authenticating user against database.');
            // Try to log the user in
            if (! Auth::attempt(['username' => $request->input('username'), 'password' => $request->input('password'), 'activated' => 1], $request->input('remember'))) {
                if (! $lockedOut) {
                    $this->incrementLoginAttempts($request);
                }

                Log::debug('Local authentication failed.');

                return redirect()->back()->withInput()->with('error', trans('auth/message.account_not_found'));
            } else {
                $this->clearLoginAttempts($request);
            }
        }

        if ($user = Auth::user()) {
            $user->last_login = \Carbon::now();
            $user->activated = 1;
            $user->save();
        }
        // Redirect to the users page
        //return redirect()->intended()->with('success', trans('auth/message.signin.success'));
        return response()->json([
                        'success' => true,
                        'message' => 'Login Success!',
                        'data'    => $user,
                        'token'   => $user->createToken('authToken')->accessToken    
                    ]);
    }
}