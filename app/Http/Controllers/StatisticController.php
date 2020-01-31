<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use App\Comment;
use App\Article;
use App\User;
use Auth;
use App\Helpers\Api;

class StatisticController extends Controller
{
    public function __construct()
    {
        $this->status   = "true";
        $this->data     = [];
        $this->errorMsg = null;
    }   

    public function index(Request $request) {
        try {

            $result = [
                'total_articles' => Article::count(),
                'total_comments' => Comment::count(),
                'total_users' => User::count(),
                'total_user_detail' => User::withCount('comments')->get(),
            ];

            $this->data = $result;
        } catch (\Exception $e) {
            $this->status   = "false";
            $this->errorMsg = $e->getMessage();
        }

        return response()->json(Api::format($this->status, $this->data, $this->errorMsg), 201);
    }

}
