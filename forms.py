# forms.py
# ----------------------------------------------------

from flask_wtf import FlaskForm
# 確保已導入所有必要的欄位類型
from wtforms import HiddenField, StringField, TextAreaField, SubmitField, PasswordField, ValidationError, DateTimeField, BooleanField, SelectField
# 確保從 flask_wtf.file 導入 FileField 和 FileAllowed
from flask_wtf.file import FileField, FileAllowed 
from wtforms.validators import DataRequired, Length, Email, EqualTo, Optional

# 定義一個用於新增儀器的表單類別
class InstrumentForm(FlaskForm):
    # 儀器代碼
    instrument_code = StringField('儀器代碼', validators=[DataRequired(), Length(max=100)])

    # 儀器中文名稱 (這部分是正確的)
    chinese_name = StringField('儀器中文名稱', validators=[DataRequired(), Length(max=100)])

    # 儀器英文名稱 
    english_name = StringField('儀器英文名稱', validators=[DataRequired(), Length(max=100)])

    # 儀器簡介 
    description = TextAreaField('儀器簡介 (用途、規格)', validators=[DataRequired()])

    # 檔案上傳欄位
    image_file = FileField('儀器圖片 (JPG/PNG/PDF)', validators=[Optional(),
        FileAllowed(['jpg', 'png', 'pdf'], '只允許上傳 .jpg, .png 或 .pdf 檔案！')])

    # 提交按鈕
    submit = SubmitField('新增儀器')

# ----------------------------------------------------

# 定義一個用於新增專案服務的表單類別
class ServiceForm(FlaskForm):
    # 專案服務代碼
    service_code = StringField('儀器代碼', validators=[DataRequired(), Length(max=100)])

    # 專案服務中文名稱 (這部分是正確的)
    chinese_name = StringField('儀器中文名稱', validators=[DataRequired(), Length(max=100)])

    # 專案服務英文名稱 
    english_name = StringField('儀器英文名稱', validators=[DataRequired(), Length(max=100)])

    # 專案服務簡介 
    description = TextAreaField('儀器簡介 (用途、規格)', validators=[DataRequired()])

    # 檔案上傳欄位
    image_file = FileField('儀器圖片 (JPG/PNG/PDF)', validators=[Optional(),
        FileAllowed(['jpg', 'png', 'pdf'], '只允許上傳 .jpg, .png 或 .pdf 檔案！')])

    # 提交按鈕
    submit = SubmitField('新增儀器')

# ----------------------------------------------------

# 使用者註冊表單 (已合併和修正重複的欄位定義)
class RegistrationForm(FlaskForm):
    # 電子郵件 (作為帳號)
    email = StringField(
        '電子郵件 (作為帳號)',
        validators=[DataRequired(), Email(), Length(max=120)]
    )

    # 真實姓名
    full_name = StringField(
        '真實姓名',
    validators=[DataRequired(), Length(max=100)]
    )

    # 所屬單位/實驗室
    affiliation = StringField(
        '所屬公司/實驗室',
        validators=[Length(max=100)]
    )

    # 密碼
    password = PasswordField(
        '密碼',
        validators=[DataRequired(), Length(min=6)]
    )


    # 確認密碼
    password2 = PasswordField(
        '確認密碼',
        validators=[DataRequired(), EqualTo('password', message='密碼必須一致')]
    )
 
    # 管理員密鑰 (選填) - 必須放在所有欄位之後，避免被覆蓋
    admin_key = StringField('管理員密鑰 (選填)', render_kw={"placeholder": "若為管理員請輸入密鑰"})

    # 提交按鈕
    submit = SubmitField('註冊帳號')

# ----------------------------------------------------

# 使用者登入表單
class LoginForm(FlaskForm):
    email = StringField(
        '電子郵件 (帳號)',
        validators=[DataRequired(), Email()]
    )

    password = PasswordField(
        '密碼',
        validators=[DataRequired()]
    )

    remember_me = BooleanField('記住我')

    submit = SubmitField('登入')

# ----------------------------------------------------

class GeneralReservationForm(FlaskForm):
    # 這是通用的預約表單
    start_time = DateTimeField('開始時間', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    end_time = DateTimeField('結束時間', format='%Y-%m-%dT%H:%M', validators=[DataRequired()])
    purpose = TextAreaField('預約目的', validators=[DataRequired(), Length(min=5, max=500)])
    submit = SubmitField('提交預約')
    
    # 用於在統一預約頁面中傳遞選中的項目ID和類型
    item_id = HiddenField()
    item_type = HiddenField()

# ----------------------------------------------------

# 總管理員表單
class SuperAdminForm(FlaskForm):
    user_id = HiddenField()

    super_key = PasswordField('總管理員密鑰', validators=[DataRequired()])
    submit = SubmitField('確認升級')

# ----------------------------------------------------

# 使用者編輯表單
class UserEditForm(FlaskForm):
    full_name = StringField('姓名', validators=[DataRequired(), Length(max=100)])
    affiliation = StringField('所屬單位/公司', validators=[DataRequired(), Length(max=100)])
    phone_number = StringField('電話號碼', validators=[Optional(), Length(max=20)])

    new_password = PasswordField('新密碼 (選填)', validators=[Optional(), Length(min=6)])

    confirm_password = PasswordField(
        '確認新密碼',
        validators=[
            Optional(),
            EqualTo('new_password', message='兩次密碼輸入不一致')
        ]
    )

    submit = SubmitField('儲存變更')

# ----------------------------------------------------