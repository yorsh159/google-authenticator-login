<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use App\Providers\RouteServiceProvider;
use Illuminate\Foundation\Auth\AuthenticatesUsers;

use Illuminate\Support\Facades\Auth;
use Illuminate\Http\Request;
use PragmaRX\Google2FA\Google2FA;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Writer as BaconQrCodeWriter;
use BaconQrCode\Renderer\Image\ImagickImageBackEnd;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;


class LoginController extends Controller
{
    /*
    |--------------------------------------------------------------------------
    | Login Controller
    |--------------------------------------------------------------------------
    |
    | This controller handles authenticating users for the application and
    | redirecting them to your home screen. The controller uses a trait
    | to conveniently provide its functionality to your applications.
    |
    */

    use AuthenticatesUsers;

    /**
     * Where to redirect users after login.
     *
     * @var string
     */
    protected $redirectTo = RouteServiceProvider::HOME;

    /**
     * Create a new controller instance.
     *
     * @return void
     */
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
    }

    public function username()
    {
        return 'codigo';
    }

    public function login(Request $request)
    {
        $this->validateLogin($request);

        if ($this->hasTooManyLoginAttempts($request)) {
            $this->fireLockoutEvent($request);

            return $this->sendLockoutResponse($request);
        }

        $user = User::where($this->username(), '=', $request->codigo)->first();

        if (password_verify($request->password, optional($user)->password)) {
            $this->clearLoginAttempts($request);

            $user->update(['token_login' => (new Google2FA)->generateSecretKey()]);

            $urlQR="";

            if(is_null($user->token_login)){
                $user->update(['token_login'=>(new Google2FA)->generateSecretKey()]);
                $urlQR = $this->createUserUrlQR($user);   
            }
        

            return view('auth2fa', compact('urlQR', 'user'));
        }

        $this->incrementLoginAttempts($request);

        return $this->sendFailedLoginResponse($request);
    }

    public function createUserUrlQR($user)
    {
        $bacon = new BaconQrCodeWriter(new ImageRenderer(
                new RendererStyle(200),
                new ImagickImageBackEnd()
            ));

        $data = $bacon->writeString(
            (new Google2FA)->getQRCodeUrl(
                config('app.name'),
                $user->codigo,
                $user->token_login
            ),
            'utf-8'
        );

        return 'data:image/png;base64,' . base64_encode($data);
    }

    public function login2FA(Request $request, User $user)
    {
        $request->validate(['code_verification' => 'required']);

        if ((new Google2FA())->verifyKey($user->token_login, $request->code_verification)) {
            $request->session()->regenerate();

            Auth::login($user);

            return redirect()->intended($this->redirectPath());
        }

        return redirect()->back()->withErrors(['error' => 'Código de verificación incorrecto']);
    }
}
