# app.py 
# ----------------------------------------------------

# 導入更多需要的函式，以便處理網頁請求、導向頁面和顯示訊息
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from wtforms import HiddenField, DateTimeField, TextAreaField, SubmitField
from wtforms.validators import DataRequired, Length
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash 
from sqlalchemy.orm import validates
from datetime import datetime, timedelta
from forms import InstrumentForm, RegistrationForm, LoginForm, GeneralReservationForm, UserEditForm, SuperAdminForm, ServiceForm
from functools import wraps


# 導入 os 模組用於路徑操作
import os 
# 導入 secure_filename 函式，用於安全處理上傳檔案名稱
from werkzeug.utils import secure_filename

# 導入 Flask-Login 相關模組
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required 


# ====== 1. Flask 應用程式初始化與配置 ======

# 初始化 Flask 應用程式
app = Flask(__name__)


# 設置檔案上傳的目標資料夾
UPLOAD_FOLDER = 'static/instrument_images' 
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# 設置服務圖片上傳資料夾
SERVICE_UPLOAD_FOLDER = 'static/service_images'
if not os.path.exists(SERVICE_UPLOAD_FOLDER):
    os.makedirs(SERVICE_UPLOAD_FOLDER)

# Flask-WTF 需要一個密鑰來保護您的表單安全 (防止 CSRF 攻擊)
app.config['SECRET_KEY'] = 'your_super_secure_key_for_flask_wtf' 
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///reservations.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 定義管理員密鑰
ADMIN_SECRET_KEY = "YourUltraSecretAdminKey1234567890"
SUPER_ADMIN_KEY = "UltraMegaSuperSecretKey_22022703" 


# ====== 2. Flask-Login 初始化 (提前到模型定義之前) ======

login_manager = LoginManager()
login_manager.init_app(app)
# 設定未登入時會被導向的函式名稱
login_manager.login_view = 'login' 

# 這是 Flask-Login 用來從資料庫載入使用者的函式 (必備！)
@login_manager.user_loader
def load_user(user_id):
    # 這裡的 user_id 是字串，需要轉換成整數
    return User.query.get(int(user_id))


# ====== 3. SQLAlchemy 模型定義 (必須在 load_user 之後) ======

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='researcher', nullable=False)
    full_name = db.Column(db.String(100), nullable=False) 
    affiliation = db.Column(db.String(100))
    unit = db.Column(db.String(100))
    phone_number = db.Column(db.String(20))
    reservations = db.relationship('Reservation', backref='user', lazy=True, 
                                   cascade="all, delete-orphan")

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Instrument(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    instrument_code = db.Column(db.String(100), unique=True, nullable=False) 
    chinese_name = db.Column(db.String(100), nullable=False) 
    english_name = db.Column(db.String(100), nullable=False) 
    description = db.Column(db.Text) 
    image_url = db.Column(db.String(255)) 
    reservations = db.relationship('Reservation', backref='instrument', lazy=True)

class Service(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    service_code = db.Column(db.String(100), unique=True, nullable=False) 
    chinese_name = db.Column(db.String(100), nullable=False)
    english_name = db.Column(db.String(100)) 
    description = db.Column(db.Text)
    image_url = db.Column(db.String(255)) 
    service_reservations = db.relationship('Reservation', backref='service', lazy=True)

class Reservation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    instrument_id = db.Column(db.Integer, db.ForeignKey('instrument.id'), nullable=True) 
    service_id = db.Column(db.Integer, db.ForeignKey('service.id'), nullable=True) 
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    start_time = db.Column(db.DateTime, nullable=False)
    end_time = db.Column(db.DateTime, nullable=False)
    purpose = db.Column(db.Text)
    status = db.Column(db.String(20), default='pending', nullable=False) 
    created_at = db.Column(db.DateTime, default=datetime.utcnow) 

    # 🌟 使用 SQLAlchemy 的 @validates 裝飾器進行模型驗證
    @validates('instrument_id', 'service_id')
    def validate_one_target(self, key, value):
        # 獲取另一個目標的值
        other_target_id = None
        
        if key == 'instrument_id':
            # 如果我們正在設置 instrument_id，則檢查 service_id
            other_target_id = self.service_id
        elif key == 'service_id':
            # 如果我們正在設置 service_id，則檢查 instrument_id
            other_target_id = self.instrument_id

        # 檢查邏輯：兩個目標必須且只能有一個有值
        # count = (1 if value is not None else 0) + (1 if other_target_id is not None else 0)
        
        # 檢查當前操作是否會導致兩個都有值
        if value is not None and other_target_id is not None:
             raise ValueError("預約只能針對一個儀器或一個服務，不能同時預約兩者。")
             
        # 檢查當前操作是否會導致兩個都為 None (這會在第一次創建時發生)
        # 最終的 'None/None' 檢查，放在表單處理時更合適
        
        return value


# ====== 4. 網站路由 (Routes) ======

@app.route('/')
def index():
    return render_template('base.html')

# 儀器列表頁面
@app.route('/instruments')
def instruments():
    instruments = Instrument.query.all()
    return render_template('instruments.html', instruments=instruments)

# 專案服務列表頁面
@app.route('/services')
def services():
    services_list = Service.query.all()
    return render_template('services.html', services=services_list)

# ------------------------------
# 🚨 修正的關鍵：確保 'login' 路由是存在的
# ------------------------------
# 登入路由
@app.route('/login', methods=['GET', 'POST'])
def login():
    # 如果使用者已經登入，直接導向首頁
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()

    if form.validate_on_submit():
        # 1. 查詢資料庫：根據 Email 查找使用者
        user = User.query.filter_by(email=form.email.data).first()

        # 2. 驗證使用者是否存在，且密碼是否匹配
        if user is None or not user.check_password(form.password.data):
            # 驗證失敗：顯示錯誤訊息
            flash('登入失敗：無效的電子郵件或密碼。', 'danger')
            # 重新顯示登入表單
            return redirect(url_for('login'))

        # 3. 驗證成功：使用 Flask-Login 建立會話
        login_user(user, remember=form.remember_me.data)

        # 4. 登入成功：導向到使用者原本想訪問的頁面，如果沒有則導向首頁
        # 這是 Flask-Login 的標準做法，讓使用者體驗更順暢
        next_page = request.args.get('next')
        return redirect(next_page) if next_page else redirect(url_for('index'))

    # 如果是 GET 請求，則顯示登入表單
    return render_template('login.html', form=form)

# 登出路由
@app.route('/logout')
def logout():
    logout_user()
    flash('您已成功登出。', 'info')
    return redirect(url_for('index'))

@login_required 
@app.route('/my_reservations')
def my_reservations():
    # 1. 查詢資料庫：獲取所有屬於當前使用者的預約紀錄
    # 篩選條件：Reservation.user_id 必須等於 current_user.id
    my_reservations = Reservation.query.filter_by(
        user_id=current_user.id
    ).order_by(Reservation.start_time.desc()).all() # 按開始時間降序排列

    # 2. 渲染模板
    return render_template('my_reservations.html', 
                            reservations=my_reservations)

# 使用者註冊路由

# 定義管理員密鑰 (請替換為您自己的密鑰！)
ADMIN_SECRET_KEY = "YourUltraSecretAdminKey1234567890"
SUPER_ADMIN_KEY = "UltraMegaSuperSecretKey_22022703" 

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        user_role = 'user'

         # 1. 檢查 Email 是否已存在 (防止 IntegrityError)
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('註冊失敗：此電子郵件地址已被註冊，請直接登入。', 'danger')
            return redirect(url_for('register'))

        # 2. 檢查密鑰邏輯 (決定角色)
        if form.admin_key.data:
            if form.admin_key.data == SUPER_ADMIN_KEY:
                user_role = 'super_admin'
                flash(f'密鑰正確，恭喜 {form.full_name.data}，您已註冊為總管理員 (Super Admin)！', 'success')
            elif form.admin_key.data == ADMIN_SECRET_KEY:
                user_role = 'admin'
                flash(f'密鑰正確，恭喜 {form.full_name.data}，您已註冊為一般管理員！', 'success')
        else:
                flash('管理員密鑰不正確，您將以普通使用者身份註冊。', 'warning')

        # 3. 創建使用者物件並加密密碼
        hashed_password = generate_password_hash(form.password.data, method='pbkdf2:sha256')

        user = User(
            full_name=form.full_name.data,
            email=form.email.data,
            affiliation=form.affiliation.data,
            # 確保使用正確的欄位名稱
            password_hash=hashed_password, 
            role=user_role 
        )

        # 4. 寫入資料庫並導向登入頁面
        db.session.add(user)
        try:
            db.session.commit()
            if user_role == 'user':
                flash('您的帳號已成功創建！請登入。', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash(f'註冊時發生資料庫錯誤：{e}', 'danger')
            return redirect(url_for('register'))

    # 渲染模板
    return render_template('register.html', title='註冊', form=form)

#管理研究員路由

@login_required
@app.route('/admin/researchers')
def admin_researchers():
    # 權限檢查：Admin 和 Super Admin 都可以看
    allowed_roles = ['admin', 'super_admin']
    if current_user.role not in allowed_roles:
        flash('權限不足！', 'danger')
        return redirect(url_for('index'))

    # 🌟 篩選邏輯：只查詢 role='user' 的使用者 🌟
    all_users = User.query.filter_by(role='user').all()

    # 注意：我們將使用新的模板 admin_researchers.html
    return render_template('admin_researchers.html', 
                            title='管理研究員', 
                            all_users=all_users)

#管理管理員路由

@login_required
@app.route('/admin/admins')
def admin_admins():
    # 權限檢查：Admin 和 Super Admin 都可以看
    allowed_roles = ['admin', 'super_admin']
    if current_user.role not in allowed_roles:
        flash('權限不足！', 'danger')
        return redirect(url_for('index'))

    # 🌟 篩選邏輯：查詢 role 在 ['admin', 'super_admin'] 中的使用者 🌟
    allowed_admin_roles = ['admin', 'super_admin']
    all_users = User.query.filter(User.role.in_(allowed_admin_roles)).all()

    # 注意：我們將使用新的模板 admin_admins.html
    return render_template('admin_admins.html', 
                            title='管理管理員', 
                            all_users=all_users)

#權限提升路由 (User -> Admin)

@login_required 
@app.route('/admin/promote/<int:user_id>')
def promote_user(user_id):
    # 1. 權限檢查：確保是 Admin
    if current_user.role != 'super_admin':
        flash('權限不足！只有總管理員才能提升其他使用者為 Admin。', 'danger')
        return redirect(url_for('admin_researchers')) # 導向回使用者列表

    # 2. 查詢該使用者紀錄
    user_to_promote = User.query.get_or_404(user_id)

    # 3. 檢查：防止 Admin 自己提升自己（雖然無意義，但安全起見）
    if user_to_promote.role == 'admin':
        flash(f'使用者 {user_to_promote.email} 已經是 Admin 角色。', 'info')
        return redirect(url_for('admin_researchers'))

    # 4. 更新狀態為 'admin'
    user_to_promote.role = 'admin'
    db.session.commit() # 🌟 提交變更到資料庫 🌟

    flash(f'使用者 {user_to_promote.email} 已成功提升為 Admin 角色！', 'success')
    return redirect(url_for('admin_researchers'))

#編輯使用者資料 (Edit User Route)

# 導入 UserEditForm (假設您在 forms.py 中定義了此表單)
# 確保您已經在 forms.py 中定義了 UserEditForm
# 編輯使用者路由 (供 Super Admin 使用)
@login_required
@app.route('/admin/user/edit/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    # 1. 權限檢查：只有 Super Admin 才能編輯使用者
    if current_user.role != 'super_admin':
        flash('權限不足！只有總管理員才能編輯使用者資料或重設密碼。', 'danger')
        # 根據用戶角色，導向正確的列表頁面
        if User.query.get(user_id) and User.query.get(user_id).role == 'user':
            return redirect(url_for('admin_researchers'))
        else:
            return redirect(url_for('admin_admins'))

    # 2. 獲取要編輯的使用者物件
    user_to_edit = User.query.get_or_404(user_id)
    form = UserEditForm(obj=user_to_edit) # 將現有資料載入到表單中

    if form.validate_on_submit():
        # A. 處理基本資料更新
        user_to_edit.full_name = form.full_name.data
        user_to_edit.affiliation = form.affiliation.data
        if hasattr(form, 'phone_number'): # 檢查表單是否有此欄位 (如果 forms.py 有定義)
            user_to_edit.phone_number = form.phone_number.data

    # B. 處理密碼重設 (選填)
        if form.new_password.data:
        # 由於密碼重設在表單驗證時（confirmpassword 欄位）已經檢查過兩次輸入是否一致
        # 這裡直接設定新密碼
            user_to_edit.set_password(form.new_password.data)
            flash('密碼已成功重設。', 'success')

        # C. 提交變更
        db.session.commit()
        flash(f'使用者 {user_to_edit.email} 的資料已成功更新。', 'success')

        # D. 導向回正確的列表頁面
        if user_to_edit.role == 'user':
            return redirect(url_for('admin_researchers'))
        else:
             return redirect(url_for('admin_admins'))

    # 3. 渲染模板 (GET 請求或表單驗證失敗)
    # 傳入 user 物件以便模板中顯示只讀的 email/role
    return render_template('edit_user.html', 
                            title='編輯使用者資料', 
                            form=form, 
                            user=user_to_edit)

#權限移除路由 (Admin -> User)

@login_required 
@app.route('/admin/demote/<int:user_id>')
def demote_user(user_id):
    # 1. 權限檢查：只允許 Super Admin 訪問
    if current_user.role != 'super_admin':
        flash('權限不足！只有總管理員才能變更管理員權限。', 'danger')
        return redirect(url_for('admin_admins'))

    user_to_demote = User.query.get_or_404(user_id)

    # 2. 防護檢查：不可移除自己的權限 (Super Admin不能降級自己)
    if user_to_demote.id == current_user.id:
        flash('您不能移除自己的權限！', 'danger')
        return redirect(url_for('admin_admins'))

    # 3. 邏輯 A：將 Super Admin 降級為 Admin
    if user_to_demote.role == 'super_admin':
        user_to_demote.role = 'admin'
        db.session.commit() # 🌟 寫入資料庫 🌟
        flash(f'使用者 {user_to_demote.email} 已降級為 Admin 角色。', 'success')
    # 4. 邏輯 B：將 Admin 降級為 User
    elif user_to_demote.role == 'admin':
        user_to_demote.role = 'user'
        db.session.commit() # 🌟 寫入資料庫 🌟
        flash(f'使用者 {user_to_demote.email} 已降級為 User 角色。', 'success')

    # 5. 如果使用者角色是 user，則無需操作
    else:
        flash(f'使用者 {user_to_demote.email} 已經是最低權限，無需變更。', 'info')

    # 6. 最終導向
    return redirect(url_for('admin_admins'))

#刪除使用者路由

@login_required 
@app.route('/admin/delete/<int:user_id>')
def delete_user(user_id):
    # 1. 權限檢查：確保是 Super Admin
    allowed_roles = ['super_admin']
    if current_user.role not in allowed_roles: 
        flash('權限不足！您沒有權限刪除使用者。', 'danger')
        return redirect(url_for('index'))

    # 2. 找到要刪除的使用者
    user_to_delete = User.query.get_or_404(user_id)

    # 3. 防護機制：防止 Admin 刪除自己的帳號 (重要!)
    if user_to_delete.id == current_user.id:
        flash('您不能刪除您自己的帳號！', 'danger')
        # 這裡應該導向管理員列表，而不是 admin_users (程式碼中沒有這個路由)
        return redirect(url_for('admin_admins')) 

    # 4. 執行刪除操作
    try:
        # 注意：Reservation 模型中已設定 cascade="all, delete-orphan"，刪除 User 時會自動刪除相關預約
        db.session.delete(user_to_delete)
        db.session.commit() # 🌟 確保這一行成功執行 🌟
        flash(f'使用者 {user_to_delete.email} 已成功從資料庫中刪除！', 'success')

    except Exception as e:
        db.session.rollback() # 如果出錯，回滾操作
        flash(f'刪除失敗：發生錯誤。錯誤：{e}', 'danger')

    # 最終導向：根據被刪除者的角色導向正確的清單
    if user_to_delete.role == 'user':
        return redirect(url_for('admin_researchers'))
    else:
        return redirect(url_for('admin_admins'))

#新增 Super Admin 升級路由

@login_required 
@app.route('/admin/promote_super/<int:target_user_id>', methods=['GET', 'POST'])
def promote_super_admin(target_user_id):
    # 1. 權限檢查：只有 Admin (admin 或 super_admin) 才能訪問這個頁面
    allowed_roles = ['admin', 'super_admin']
    if current_user.role not in allowed_roles:
        flash('權限不足！您沒有權限訪問此管理頁面。', 'danger')
        return redirect(url_for('index'))

    # 2. 確保只有 Super Admin 才能執行寫入操作
    if current_user.role != 'super_admin':
        flash('您需要總管理員權限才能執行此操作。', 'danger')
        return redirect(url_for('admin_admins'))

    # 3. 實例化表單並獲取目標使用者
    # 🚨 修正：您需要在 forms.py 中定義 Form，並確保已在頂部導入。
    try:
        from forms import SuperAdminForm
    except ImportError:
        # 如果 forms.py 中沒有這個表單，您將需要在該檔案中添加它
        flash("錯誤：缺少 SuperAdminForm 定義。請檢查 forms.py。", 'danger')
        return redirect(url_for('admin_admins'))

    form = SuperAdminForm()
    user_to_promote = User.query.get_or_404(target_user_id)

    # 4. 處理表單提交
    if form.validate_on_submit():
        if form.super_key.data == SUPER_ADMIN_KEY:
            # 密鑰正確，執行升級
            user_to_promote.role = 'super_admin'
            db.session.commit()
            flash(f'使用者 {user_to_promote.email} 已成功升級為總管理員 (Super Admin)！', 'success')
            return redirect(url_for('admin_admins'))
        else:
            # 密鑰錯誤
            flash('總管理員密鑰不正確，升級失敗。', 'danger')

    # 5. 渲染模板
    return render_template('promote_super_admin.html', 
                            form=form, 
                            user=user_to_promote,
                            target_user_id=target_user_id)

@login_required
@app.route('/instrument/<int:instrument_id>', methods=['GET', 'POST'])
def instrument_detail(instrument_id):
    instrument = Instrument.query.get_or_404(instrument_id)
    form = GeneralReservationForm()
    current_time = datetime.now()
    
    # 🌟 關鍵修正：在驗證之前，強制設定 item_id 和 item_type 的值 🌟
    # 這是確保 DataRequired 驗證通過的關鍵步驟
    if request.method == 'POST':
        form.item_id.data = instrument_id
        form.item_type.data = 'instrument' # 修正：補上結束引號
    
    if form.validate_on_submit():
        
        # 由於我們已經在上面設定了 data，這裡可以省略重複賦值，
        # 讓程式碼更簡潔，但如果保留也可以，只是有點多餘。
        # form.item_id.data = instrument_id
        # form.item_type.data = 'instrument' # 再次修正：補上結束引號
        
        item_id = form.item_id.data
        item_type = form.item_type.data
        start_time = form.start_time.data
        end_time = form.end_time.data
        
        # 1. 時間邏輯檢查
        if start_time >= end_time:
            flash('預約失敗：開始時間必須早於結束時間。', 'danger') # 修正：補上結束引號和括號

        else:
            # 2. 衝突檢查邏輯
            conflict_reservations = Reservation.query.filter(
                Reservation.instrument_id == item_id, # 使用 item_id
                Reservation.status.in_(['confirmed', 'pending']),
                Reservation.start_time < end_time,
                Reservation.end_time > start_time
            ).all()
            
            if conflict_reservations:
                flash('預約失敗：您選擇的時段與現有預約發生衝突！請檢查時間。', 'danger')
                
            else:
                # 3. 提交預約物件
                try:
                    new_reservation = Reservation(
                        instrument_id=item_id, # 使用 item_id
                        user_id=current_user.id,
                        start_time=start_time,
                        end_time=end_time,
                        purpose=form.purpose.data,
                        status='pending'
                    )
                    
                    db.session.add(new_reservation)
                    db.session.commit()
                    
                    flash('您的儀器預約已提交成功，等待管理員審核。', 'success')
                    return redirect(url_for('instrument_detail', instrument_id=instrument.id))
                
                except Exception as e:
                    db.session.rollback()
                    flash(f'預約提交時發生資料庫錯誤。請聯繫管理員。', 'danger') 
                    print(f"Database Error on instrument reservation: {e}") 

    # GET 請求時設定預設時間
    if request.method == 'GET':
        now_clean = current_time.replace(second=0, microsecond=0)
        form.start_time.data = now_clean
        form.end_time.data = now_clean + timedelta(hours=2)

    # 渲染模板，顯示確認預約
    confirmed_reservations = Reservation.query.filter(
        Reservation.instrument_id == instrument.id,
        Reservation.status == 'confirmed',
        Reservation.end_time >= current_time
    ).order_by(Reservation.start_time.asc()).all()

    return render_template('instrument_detail.html', 
                           form=form, 
                           instrument=instrument,
                           confirmed_reservations=confirmed_reservations)

# 輔助函式：檢查使用者是否為管理員
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 確保 current_user 已經被導入 (from flask_login import current_user)
        # 這裡檢查 current_user 的 role 屬性
        if not current_user.is_authenticated or current_user.role not in ['admin', 'super_admin']:
            flash('您沒有管理員權限訪問該頁面。', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# 輔助函式：檢查使用者是否為總管理員 (可選)
def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'super_admin':
            flash('您沒有超級管理員權限訪問該頁面。', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# 確保使用者必須登入才能訪問這個頁面
@login_required
@app.route('/admin/add_instrument', methods=['GET', 'POST'])
def add_instrument():

    # 🌟 角色檢查開始 🌟
    allowed_roles = ['admin', 'super_admin']
    if current_user.role not in allowed_roles:
        flash('權限不足！您沒有權限訪問此管理頁面。', 'danger')
        return redirect(url_for('index'))
    # 🌟 角色檢查結束 🌟

    # 只有 admin 角色才能執行下面的程式碼
    # 🌟 步驟 1: 創建表單實例 (這行必須在最前面)
    form = InstrumentForm() 

    # 檢查是否為 POST 提交且資料有效
    if form.validate_on_submit():

        image_filename = None
        # 🚨 關鍵：處理檔案上傳
        if form.image_file.data:
            # 確保這裡沒有隱藏的執行路徑會導致提前返回 None
            try:
                # 您的圖片處理邏輯...
                filename = secure_filename(form.image_file.data.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                form.image_file.data.save(file_path)
                image_url = filename
            except Exception as e:
                # 💡 如果圖片上傳失敗，必須立即返回一個響應
                flash(f'圖片上傳失敗：{e}', 'danger')
                return render_template('add_instrument.html', title='新增儀器', form=form) # 👈 修正點：錯誤時返回渲染模板

        # 1. 取得表單資料
        new_instrument = Instrument(
            instrument_code=form.instrument_code.data,

            chinese_name=form.chinese_name.data,
            english_name=form.english_name.data,
            description=form.description.data,
            image_url=image_filename # 寫入檔案路徑 (e.g. 'instrument_images/my_file.jpg')
        )

        # 2. 將資料寫入資料庫
        try:
            db.session.add(new_instrument)
            db.session.commit()
            flash(f'儀器 "{new_instrument.chinese_name}" 新增成功！', 'success')
            return redirect(url_for('instruments')) 
        except Exception as e:
            db.session.rollback()
            flash(f'新增儀器時發生錯誤：{e}', 'danger')
            # ❗ 即使資料庫操作失敗，程式碼也會繼續往下執行，最終到達第 2 點的 return 語句。

    # 🌟 步驟 2: 如果是 GET 請求，或 POST 驗證失敗，就執行這行
    # 這確保了 'form' 永遠會被傳遞給模板s83
    return render_template('add_instrument.html', title='新增儀器', form=form)

@login_required
@admin_required # 確保只有管理員能訪問
@app.route('/admin/edit_instrument/<int:instrument_id>', methods=['GET', 'POST'])
def edit_instrument(instrument_id):
    # 獲取要編輯的儀器物件
    instrument = Instrument.query.get_or_404(instrument_id)
    form = InstrumentForm(obj=instrument) # 💡 使用 obj=instrument 預填充表單

    if form.validate_on_submit():
        # 處理圖片上傳
        image_url = instrument.image_url # 預設保留舊圖片

        if form.image_file.data:
            # 💡 這裡應該包含刪除舊圖片的邏輯 (可選)
            try:
                filename = secure_filename(form.image_file.data.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                form.image_file.data.save(file_path)
                image_url = filename
            except Exception as e:
                flash(f'圖片上傳失敗：{e}', 'danger')
                return render_template('edit_instrument.html', form=form, instrument=instrument)

        # 更新儀器物件的屬性
        instrument.instrument_code = form.instrument_code.data
        instrument.chinese_name = form.chinese_name.data
        instrument.english_name = form.english_name.data
        instrument.description = form.description.data
        instrument.image_url = image_url

        try:
            db.session.commit()
            flash(f'儀器 "{instrument.chinese_name}" 已成功更新！', 'success')
            return redirect(url_for('instrument_detail', instrument_id=instrument.id))
        except Exception as e:
            db.session.rollback()
            flash(f'更新儀器時發生錯誤：{e}', 'danger')
    
    elif request.method == 'GET':
        # 預填充表單資料 (Flask-WTF的 obj=instrument 已經處理，這裡可選)
        pass 
        
    return render_template('edit_instrument.html', title='編輯儀器', form=form, instrument=instrument)

@login_required
@admin_required # 確保只有管理員能訪問
@app.route('/admin/delete_instrument/<int:instrument_id>', methods=['POST'])
def delete_instrument(instrument_id):
    instrument = Instrument.query.get_or_404(instrument_id)

    # 💡 這裡應該包含刪除相關預約紀錄和儲存圖片檔案的邏輯 (重要)
    
    instrument_name = instrument.chinese_name
    try:
        db.session.delete(instrument)
        db.session.commit()
        flash(f'儀器 "{instrument_name}" 已成功刪除。', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'刪除儀器時發生錯誤：{e}', 'danger')
        
    return redirect(url_for('instruments'))

# ----------------------------------------------------
# 🌟 新增：管理員新增專案服務 🌟
# ----------------------------------------------------

@login_required
@app.route('/admin/add_service', methods=['GET', 'POST'])
def add_service():
    # 1. 權限檢查：只有 admin 或 super_admin 才能訪問
    allowed_roles = ['admin', 'super_admin']
    if current_user.role not in allowed_roles:
        flash('權限不足！您沒有權限訪問此管理頁面。', 'danger')
        return redirect(url_for('index'))

    # 2. 創建表單實例
    form = ServiceForm() 
    if form.validate_on_submit():
        # 🚨 修正 1: 修正拼寫錯誤 'Noene' 為 None
        image_filename = None

        # 🚨 修正 2: 補回檔案上傳處理 (如果您的 ServiceForm 有 image_file 欄位)
        if hasattr(form, 'image_file') and form.image_file.data:
            uploaded_file = form.image_file.data
            filename = secure_filename(uploaded_file.filename)

            # 💡 建議：將服務圖片存入 service_images 資料夾以區分
            SERVICE_UPLOAD_FOLDER = 'static/service_images'
            if not os.path.exists(SERVICE_UPLOAD_FOLDER):
                 os.makedirs(SERVICE_UPLOAD_FOLDER)

            filepath = os.path.join(SERVICE_UPLOAD_FOLDER, filename)
            uploaded_file.save(filepath)

            # 儲存相對路徑
            image_filename = os.path.join('service_images', filename) 


        # 3. 創建 Service 物件
        # 🚨 修正 3: 確保傳遞所有需要的欄位，例如 service_code, image_url
        new_service = Service(
            # 確保 Service 模型有這個欄位
            service_code=form.service_code.data, 
            chinese_name=form.chinese_name.data,
            english_name=form.english_name.data,
            description=form.description.data,
            image_url=image_filename # 寫入圖片路徑，如果沒有上傳，則為 None
        )

       # 4. 寫入資料庫 - 使用 try...except 處理潛在錯誤 (如 service_code 重複)
        try:
            db.session.add(new_service)
            db.session.commit()

# 5. 提示並導向
            flash(f'專案服務 "{new_service.chinese_name}" 已成功新增！', 'success')
            # 🌟 導向到服務詳情頁面
            return redirect(url_for('service_detail', service_id=new_service.id))

        except Exception as e:
            db.session.rollback()
            # 🌟 增加錯誤提示：可能是 service_code 重複導致的 IntegrityError
            flash(f'新增專案服務失敗：代碼重複或資料庫錯誤。請檢查輸入。錯誤：{e}', 'danger')
            # 🌟 失敗時，返回到表單頁面
            return render_template('add_service.html', form=form)

# 6. 渲染模板 (GET 請求或 POST 失敗)
    return render_template('add_service.html', form=form)

@login_required
@admin_required
@app.route('/admin/edit_service/<int:service_id>', methods=['GET', 'POST'])
def edit_service(service_id):
    service = Service.query.get_or_404(service_id)
    form = ServiceForm(obj=service) 

    if form.validate_on_submit():
        image_url = service.image_url

        if form.image_file.data:
            # 處理圖片上傳邏輯，確保儲存到正確的服務圖片路徑
            # ... (與 edit_instrument 類似的圖片處理邏輯) ...
            try:
                filename = secure_filename(form.image_file.data.filename)
                # 假設 SERVICE_UPLOAD_FOLDER 已定義
                file_path = os.path.join(app.config.get('SERVICE_UPLOAD_FOLDER', 'static/service_images'), filename)
                form.image_file.data.save(file_path)
                image_url = os.path.join('service_images', filename)
            except Exception as e:
                flash(f'圖片上傳失敗：{e}', 'danger')
                return render_template('edit_service.html', form=form, service=service)


        # 更新服務物件的屬性
        service.service_code = form.service_code.data
        service.chinese_name = form.chinese_name.data
        service.english_name = form.english_name.data
        service.description = form.description.data
        service.image_url = image_url

        try:
            db.session.commit()
            flash(f'專案服務 "{service.chinese_name}" 已成功更新！', 'success')
            return redirect(url_for('service_detail', service_id=service.id))
        except Exception as e:
            db.session.rollback()
            flash(f'更新專案服務時發生錯誤：{e}', 'danger')
            
    return render_template('edit_service.html', title='編輯專案服務', form=form, service=service)

@login_required
@admin_required
@app.route('/admin/delete_service/<int:service_id>', methods=['POST'])
def delete_service(service_id):
    service = Service.query.get_or_404(service_id)
    service_name = service.chinese_name
    
    # 💡 這裡應該包含刪除相關預約紀錄和儲存圖片檔案的邏輯 (重要)

    try:
        db.session.delete(service)
        db.session.commit()
        flash(f'專案服務 "{service_name}" 已成功刪除。', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'刪除專案服務時發生錯誤：{e}', 'danger')
        
    return redirect(url_for('services'))

@login_required 
@app.route('/admin/reservations')
def admin_reservations():
    # 1. 權限檢查：只有 admin 才能訪問
    allowed_roles = ['admin', 'super_admin']
    if current_user.role not in allowed_roles:
        flash('權限不足！您沒有權限訪問此管理頁面。', 'danger')
        return redirect(url_for('index'))

    # 2. 查詢資料庫：獲取所有狀態為 'pending' 的預約紀錄
    # 🌟 使用 filter_by 篩選出 instrument_id 和 status
    pending_reservations = Reservation.query.filter_by(
        status='pending'
    ).order_by(Reservation.created_at.asc()).all() # 按照建立時間升序排列

    # 3. 渲染模板
    return render_template('admin_reservations.html', 
                            pending_reservations=pending_reservations)

# 輔助函式：檢查使用者是否為管理員
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 確保 current_user 已經被導入 (from flask_login import current_user)
        # 這裡檢查 current_user 的 role 屬性
        if not current_user.is_authenticated or current_user.role not in ['admin', 'super_admin']:
            flash('您沒有管理員權限訪問該頁面。', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# 輔助函式：檢查使用者是否為總管理員 (可選)
def super_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'super_admin':
            flash('您沒有超級管理員權限訪問該頁面。', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# --- 批准預約路由 ---
@app.route('/approve_reservation/<int:reservation_id>', methods=['POST'])
@login_required
@admin_required 
def approve_reservation(reservation_id):
    # 這裡的 Reservation 必須是您在 app.py 中導入的模型
    reservation = Reservation.query.get_or_404(reservation_id)
    
    if reservation.status == 'pending':
        reservation.status = 'confirmed'
        # 🌟 您可以在這裡添加檢查，確保批准後沒有新的時間衝突發生
        # 由於您之前已經成功創建了預約，這裡先簡單處理狀態變更
        
        db.session.commit()
        flash(f'預約 #{reservation_id} 已批准。', 'success')
    else:
        flash('只有待處理的預約才能被批准。', 'danger')
        
    return redirect(url_for('admin_reservations')) 


### 2\. 拒絕預約 (Reject Reservation)

# --- 拒絕預約路由 ---
@app.route('/reject_reservation/<int:reservation_id>', methods=['POST'])
@login_required
@admin_required
def reject_reservation(reservation_id):
    reservation = Reservation.query.get_or_404(reservation_id)
    
    if reservation.status == 'pending':
        reservation.status = 'rejected'
        db.session.commit()
        flash(f'預約 #{reservation_id} 已拒絕。', 'success')
    else:
        flash('該預約狀態不允許拒絕。', 'danger')
        
    return redirect(url_for('admin_reservations')) 



# 專案服務詳情及預約路由
@login_required
@app.route('/service/<int:service_id>', methods=['GET', 'POST'])
def service_detail(service_id):
    service = Service.query.get_or_404(service_id)
    form = GeneralReservationForm()
    current_time = datetime.now()

    if form.validate_on_submit():
        start_time = form.start_time.data
        end_time = form.end_time.data

        if start_time >= end_time:
            flash('預約失敗：開始時間必須早於結束時間。', 'danger')
        else:
            conflict_reservations = Reservation.query.filter(
                Reservation.service_id == service.id,
                Reservation.status.in_(['confirmed', 'pending']),
                Reservation.start_time < end_time,
                Reservation.end_time > start_time
            ).all()

            if conflict_reservations:
                flash('預約失敗：您選擇的時段與現有預約發生衝突！', 'danger')
            else:
                try:
                    new_reservation = Reservation(
                        service_id=service.id,  
                        user_id=current_user.id,
                        start_time=start_time,
                        end_time=end_time,
                        purpose=form.purpose.data,
                        status='pending'
                    )
                    
                    db.session.add(new_reservation)
                    db.session.commit()
                    
                    flash('您的專案服務預約已提交成功，等待管理員審核。', 'success')
                    return redirect(url_for('service_detail', service_id=service.id))
                
                except Exception as e:
                    db.session.rollback()
                    flash(f'預約提交時發生資料庫錯誤。請聯繫管理員。', 'danger')
                    print(f"Database Error on service reservation: {e}") 

    if request.method == 'GET':
        now_clean = current_time.replace(second=0, microsecond=0)
        form.start_time.data = now_clean
        form.end_time.data = now_clean + timedelta(hours=2)

    confirmed_reservations = Reservation.query.filter(
        Reservation.service_id == service.id,
        Reservation.status == 'confirmed',
        Reservation.end_time >= current_time
    ).order_by(Reservation.start_time.asc()).all()

    return render_template('service_detail.html', 
                           form=form, 
                           service=service,
                           confirmed_reservations=confirmed_reservations)


# app.py 路由部分 (已修正 NameError, 縮排錯誤, 並加入了提交邏輯)

@app.route('/general_reserve', methods=['GET', 'POST'])
@login_required
def general_reserve():
    form = GeneralReservationForm()
    instruments = Instrument.query.order_by(Instrument.instrument_code.asc()).all()
    services = Service.query.order_by(Service.service_code.asc()).all()

    # 1. 處理 POST 請求 (表單提交)
    if form.validate_on_submit():
        
        # 🚨 關鍵修正：優先從強制傳輸欄位獲取值 (最保險的數據源)
        item_id = request.form.get('force_item_id')
        item_type = request.form.get('force_item_type')
    
        # 如果強制欄位為空 (JS 無效)，則回退到 instrument_id/service_id
        if not item_id:
            instrument_id = request.form.get('instrument_id')
            service_id = request.form.get('service_id')

            if instrument_id:
                item_id = instrument_id
                item_type = 'instrument'
            elif service_id:
                item_id = service_id
                item_type = 'service'
            
        # 🚨 DEBUG: 輸出收到的值 (這是最終的確認！)
        print(f"DEBUG_POST: item_type={item_type}, item_id={item_id}")
        # 從 WTForms 獲取時間和其他欄位
        start_time = form.start_time.data
        end_time = form.end_time.data
        
        # 🌟 額外驗證：確保有選擇項目
        # item_id 和 item_type 都是 None 時會觸發
        if not item_id or not item_type:
            flash('預約失敗：請選擇您要預約的儀器或服務。', 'danger')
            # 驗證失敗時，讓程式碼繼續到最後的 return render_template
            
        # 額外驗證：時間邏輯檢查
        elif start_time >= end_time:
            flash('預約失敗：開始時間必須早於結束時間。', 'danger')
            
        else:
            # 嘗試轉換 item_id
            try:
                item_id = int(item_id)
            except (ValueError, TypeError):
                flash('預約失敗：項目 ID 無效。', 'danger')
                return render_template('general_reserve.html', form=form, instruments=instruments, services=services)

            # 設置衝突檢查條件
            conflict_filter = [
                # ... (您的衝突檢查邏輯不變) ...
                Reservation.status.in_(['confirmed', 'pending']),
                Reservation.start_time < end_time,
                Reservation.end_time > start_time
            ]
            
            # 根據類型添加過濾條件
            if item_type == 'instrument':
                conflict_filter.append(Reservation.instrument_id == item_id)
            elif item_type == 'service':
                conflict_filter.append(Reservation.service_id == item_id)
            
            # 執行時間衝突查詢
            conflict_reservations = Reservation.query.filter(*conflict_filter).all()
            
            if conflict_reservations:
                flash('預約失敗：您選擇的時段與現有預約發生衝突！請檢查時間。', 'danger')
            else:
                # 提交預約物件
                try:
                    new_reservation = Reservation(
                        user_id=current_user.id,
                        start_time=start_time,
                        end_time=end_time,
                        purpose=form.purpose.data,
                        status='pending'
                    )
                    
                    if item_type == 'instrument':
                        new_reservation.instrument_id = item_id
                    elif item_type == 'service':
                        new_reservation.service_id = item_id
                        
                    db.session.add(new_reservation)
                    db.session.commit()
                    
                    flash('預約已提交，等待管理員審核。', 'success')
                    return redirect(url_for('my_reservations'))
                    
                except Exception as e:
                    db.session.rollback()
                    error_message = f'預約失敗：資料庫錯誤。詳細：{e}'
                    flash(error_message, 'danger')
                    print(f"General Reservation Database Commit Failed: {e}")
            
    # 2. 處理 GET 請求或 POST 驗證失敗的情況 (此部分保留在 if 塊外部，以便在任何情況下渲染模板)
    if request.method == 'GET':
        current_time = datetime.now()
        now_clean = current_time.replace(second=0, microsecond=0)
        
        if form.start_time.data is None:
            form.start_time.data = now_clean
        if form.end_time.data is None:
            form.end_time.data = now_clean + timedelta(hours=2)
            
    # 3. 渲染模板
    return render_template(
        'general_reserve.html',
        form=form,
        instruments=instruments,
        services=services
    )

# ------------------------------
# 🚨 確保您的所有其他路由都放在這裡
# ------------------------------


# 應用程式的啟動點
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("資料庫表格已檢查並建立完成 (reservations.db)。")

    app.run(debug=True)
