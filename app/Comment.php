<?php

namespace App;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\SoftDeletes;

class Comment extends Model
{
    use SoftDeletes;

    public $primaryKey = 'id';
    protected $table = 'comments';
    protected $guarded = ['id'];
    protected $dates =['deleted_at'];

    public function users(){
        return $this->belongsTo('App\User', 'user_id', 'id');
    }

    public function articles(){
        return $this->belongsTo('App\Article', 'article_id', 'id');
    }
}
