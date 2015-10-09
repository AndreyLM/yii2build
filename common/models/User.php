<?php
namespace common\models;

use Yii;
use yii\base\NotSupportedException;
use yii\behaviors\TimestampBehavior;
use yii\db\ActiveRecord;
use yii\db\Exception;
use yii\db\Expression;
use yii\helpers\ArrayHelper;
use yii\web\IdentityInterface;
use yii\base\Security;
use backend\models\Role;
use backend\models\Status;
use backend\models\UserType;
use frontend\models\Profile;
use yii\helpers\Url;
use yii\helpers\Html;

/**
 * User model
 *
 * @property integer $id
 * @property string $username
 * @property string $password_hash
 * @property string $password_reset_token
 * @property string $email
 * @property string $auth_key
 * @property integer $role_id
 * @property integer $user_type_id
 * @property integer $status_id
 * @property integer $created_at
 * @property integer $updated_at
 * @property string $password write-only password
 */
class User extends ActiveRecord implements IdentityInterface
{
    const STATUS_DELETED = 0;
    const STATUS_ACTIVE = 10;

    /**
     * @inheritdoc
     */
    public static function tableName()
    {
        return 'user';
    }

    /**
     * @inheritdoc
     */

    public function behaviors()
    {
        return [
            'timestamp'=> [
                'class'=>'yii\behaviors\TimestampBehavior',
                'attributes'=> [
                    ActiveRecord::EVENT_BEFORE_INSERT=>['created_at', 'updated_at'],
                    ActiveRecord::EVENT_AFTER_UPDATE=>['updated_at'],
                ],
            'value'=> new Expression('NOW()'),
            ],

        ];
    }

    /**
     * @inheritdoc
     */
    public function rules()
    {
        return [
            ['status_id', 'default', 'value' => self::STATUS_ACTIVE],
            ['status_id', 'in', 'range'=>array_keys($this->getStatusList())],
            ['role_id', 'default', 'value' => 10],
            ['role_id', 'in', 'range'=>array_keys($this->getRoleList())],
            ['user_type_id', 'default', 'value'=>10],
            ['user_type_id', 'in', 'range'=>array_keys($this->getUserTypeList())],
            ['username', 'filter', 'filter'=>'trim'],
            ['username', 'required'],
            ['username', 'unique'],
            ['username', 'string', 'min'=>2, 'max'=>255],
            ['email', 'filter', 'filter'=>'trim'],
            ['email', 'required'],
            ['email', 'email'],
            ['email', 'unique'],
        ];
    }

    /**
     * @inheritdoc
     */
    public static function findIdentity($id)
    {
        return static::findOne(['id' => $id, 'status_id' => self::STATUS_ACTIVE]);
    }

    /**
     * @inheritdoc
     */
    public static function findIdentityByAccessToken($token, $type = null)
    {
        return static::findOne(['auth_key'=>$token]);
    }

    /**
     * Finds user by username
     *
     * @param string $username
     * @return static|null
     */
    public static function findByUsername($username)
    {
        return static::findOne(['username' => $username, 'status_id' => self::STATUS_ACTIVE]);
    }

    /**
     * Finds user by password reset token
     *
     * @param string $token password reset token
     * @return static|null
     */
    public static function findByPasswordResetToken($token)
    {

        $expire=Yii::$app->params['user.passwordResetTokenExpire'];
        $parts=explode('_', $token);
        $timestamp=(int) end($parts);

        if($timestamp+$expire<time()) {
            return null;
        }


        return static::findOne([
            'password_reset_token' => $token,
            'status_id' => self::STATUS_ACTIVE,
        ]);
    }

    /**
     * Finds out if password reset token is valid
     *
     * @param string $token password reset token
     * @return boolean
     */
    public static function isPasswordResetTokenValid($token)
    {
        if (empty($token)) {
            return false;
        }
        $expire = Yii::$app->params['user.passwordResetTokenExpire'];
        $parts = explode('_', $token);
        $timestamp = (int) end($parts);
        return $timestamp + $expire >= time();
    }

    /**
     * @inheritdoc
     */
    public function getId()
    {
        return $this->getPrimaryKey();
    }

    /**
     * @inheritdoc
     */
    public function getAuthKey()
    {
        return $this->auth_key;
    }

    /**
     * @inheritdoc
     */
    public function validateAuthKey($authKey)
    {
        return $this->getAuthKey() === $authKey;
    }

    /**
     * Validates password
     *
     * @param string $password password to validate
     * @return boolean if password provided is valid for current user
     */
    public function validatePassword($password)
    {
        return Yii::$app->security->validatePassword($password, $this->password_hash);
    }

    /**
     * Generates password hash from password and sets it to the model
     *
     * @param string $password
     */
    public function setPassword($password)
    {
        $this->password_hash = Yii::$app->security->generatePasswordHash($password);
    }

    /**
     * Generates "remember me" authentication key
     */
    public function generateAuthKey()
    {
        $this->auth_key = Yii::$app->security->generateRandomString();
    }

    /**
     * Generates new password reset token
     */
    public function generatePasswordResetToken()
    {
        $this->password_reset_token = Yii::$app->security->generateRandomString() . '_' . time();
    }

    /**
     * Removes password reset token
     */
    public function removePasswordResetToken()
    {
        $this->password_reset_token = null;
    }

    public function getRole()
    {
        return $this->hasOne(Role::className(), ['role_value'=>'role_id']);
    }

    public function getRoleName()
    {
        return $this->role ? $this->role->role_name : '- no role -';
    }

    public static function getRoleList()
    {
        $dropitems=Role::find()->asArray()->all();
        return ArrayHelper::map($dropitems, 'role_value', 'role_name');
    }

    public function getStatus()
    {
        return $this->hasOne(Status::className(), ['status_value'=>'status_id']);
    }

    public function getStatusList()
    {
        $arr=Status::find()->asArray()->all();
        return ArrayHelper::map($arr, 'status_value', 'status_name');
    }

    public function getStatusName()
    {
        return $this->status ? $this->status->status_name : '-no status-';
    }

    public function getUserType()
    {
        return $this->hasOne(UserType::className(), ['user_type_value'=>'user_type_id']);
    }

    public function getUserTypeName()
    {
        return $this->userType ? $this->userType->user_type_name : '- no user type name -';
    }

    public function getUserTypeList()
    {
        $arr=UserType::find()->asArray()->all();
        return ArrayHelper::map($arr, 'user_type_value', 'user_type_name');
    }

    public function getUserTypeId()
    {
        return $this->userType ? $this->userType->id : 'none';
    }

    public function getProfile()
    {
        return $this->hasOne(Profile::className(), ['user_id'=>'id']);
    }

    public  function getProfileId()
    {
        return $this->profile ? $this->profile->id : 'none';
    }

    public function getProfileLink()
    {
        $url=Url::to(['profile/view', 'id'=>$this->profileId]);
        $options=[];
        return Html::a($this->profile ? 'profile' : 'none', $url, $options);
    }

    public function getUserIdLink()
    {
        $url = Url::to(['user/update', 'id'=>$this->id]);
        $options=[];
        return Html::(($this->id, $url, $options);
    }

    public function getUserLink()
    {
        $url = Url::to(['user/view', 'id'=>$this->id]);
        $options=[];
        return Html::a($this->username, $url, $options);
    }

    public function attributeLabels()
    {
        return [
          'roleName' => Yii::t('app', 'Role'),
          'statusName' => Yii::t('app', 'Status'),
          'profileId' => Yii::t('app', 'Profile'),
          'profileLink' => Yii::t('app', 'Profile'),
          'userLink' => Yii::t('app', 'User'),
          'userTypeName' => Yii::t('app', 'User Type'),
          'userTypeId' => Yii::t('app', 'User Type'),
          'userTypeLink' => Yii::t('app', 'User Type'),
        ];
    }
}
