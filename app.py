import os
import uuid
from datetime import datetime, date, timezone
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, abort, jsonify
from flask_wtf.csrf import CSRFProtect

from config import Config
from models import db, User, StudentProfile, Room, RoomRequest, RoomAllocation, Bill, Payment
from forms import (
    LoginForm, StudentRegisterForm, StudentProfileForm, AdminStudentForm,
    ChangePasswordForm, RoomForm, RoomRequestForm, RoomAllocationForm,
    BillForm, PaymentForm
)

csrf = CSRFProtect()

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    db.init_app(app)
    csrf.init_app(app)

    # ----------------------------------------------------
    # Custom Context Processors and Template Filters
    # ----------------------------------------------------
    @app.context_processor
    def inject_current_user():
        current_user = None
        student_profile = None
        if 'user_id' in session:
            current_user = db.session.get(User, session['user_id'])
            if current_user and current_user.is_student:
                student_profile = current_user.student_profile
        return dict(
            current_user=current_user,
            student_profile=student_profile,
            now=datetime.now(timezone.utc)
        )

    @app.template_filter('currency')
    def currency_filter(value):
        try:
            return f"₹{float(value):,.2f}"
        except (ValueError, TypeError):
            return "₹0.00"

    @app.template_filter('format_date')
    def format_date_filter(value, fmt='%d %b %Y'):
        if not value:
            return '-'
        if isinstance(value, (datetime, date)):
            return value.strftime(fmt)
        return str(value)

    # ----------------------------------------------------
    # Authentication & Authorization Helpers
    # ----------------------------------------------------
    def login_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login', next=request.url))
            user = db.session.get(User, session['user_id'])
            if not user or not user.is_active:
                session.clear()
                flash('Your account is inactive or not found. Please contact administration.', 'danger')
                return redirect(url_for('login'))
            return f(*args, **kwargs)
        return decorated_function

    def admin_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login', next=request.url))
            if session.get('role') != 'admin':
                abort(403)
            return f(*args, **kwargs)
        return decorated_function

    def student_required(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_id' not in session:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login', next=request.url))
            if session.get('role') != 'student':
                abort(403)
            return f(*args, **kwargs)
        return decorated_function

    # ----------------------------------------------------
    # Error Handlers
    # ----------------------------------------------------
    @app.errorhandler(400)
    def bad_request(e):
        return render_template('errors/400.html'), 400

    @app.errorhandler(403)
    def forbidden(e):
        return render_template('errors/403.html'), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def server_error(e):
        return render_template('errors/500.html'), 500

    # ----------------------------------------------------
    # Health Check Endpoint for Render, Docker & Kubernetes
    # ----------------------------------------------------
    @app.route('/health')
    def health_check():
        try:
            # Active lightweight ping to verify database connectivity
            db.session.execute(db.select(1)).scalar()
        except Exception as e:
            app.logger.error(f"Health check database failure: {e}")
            return jsonify({
                "status": "unhealthy",
                "database": "unavailable",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 503

        return jsonify({
            "status": "healthy",
            "database": "connected",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "environment": os.environ.get('FLASK_ENV', 'development')
        }), 200

    # ----------------------------------------------------
    # Public Routes
    # ----------------------------------------------------
    @app.route('/')
    def index():
        total_rooms = Room.query.count()
        vacant_rooms = sum(1 for r in Room.query.all() if r.status == 'Vacant')
        return render_template('index.html', total_rooms=total_rooms, vacant_rooms=vacant_rooms)

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if 'user_id' in session:
            if session.get('role') == 'admin':
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('student_dashboard'))

        form = LoginForm()
        if form.validate_on_submit():
            input_val = form.username.data.strip()
            password = form.password.data

            # Try by username or student roll number or email
            user = User.query.filter((User.username == input_val) | (User.email == input_val)).first()
            if not user:
                # Check student_profile student_id
                sp = StudentProfile.query.filter_by(student_id=input_val).first()
                if sp:
                    user = sp.user

            if user and user.check_password(password):
                if not user.is_active:
                    flash('Your account has been deactivated. Please contact the hostel office.', 'danger')
                    return render_template('login.html', form=form)

                session.clear()
                session['user_id'] = user.id
                session['username'] = user.username
                session['role'] = user.role

                flash(f'Welcome back, {user.username}!', 'success')
                next_url = request.args.get('next')
                if next_url and next_url.startswith('/'):
                    return redirect(next_url)

                if user.is_admin:
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('student_dashboard'))
            else:
                flash('Invalid credentials. Please verify your username/ID and password.', 'danger')

        return render_template('login.html', form=form)

    @app.route('/register', methods=['GET', 'POST'])
    def register():
        if 'user_id' in session:
            return redirect(url_for('index'))

        form = StudentRegisterForm()
        if form.validate_on_submit():
            # Check unique constraints
            if User.query.filter_by(username=form.username.data.strip()).first():
                flash('Username already registered. Please choose another username.', 'danger')
                return render_template('register.html', form=form)

            if User.query.filter_by(email=form.email.data.strip().lower()).first():
                flash('Email address already registered.', 'danger')
                return render_template('register.html', form=form)

            if StudentProfile.query.filter_by(student_id=form.student_id.data.strip()).first():
                flash('Student Roll/ID already registered in the system.', 'danger')
                return render_template('register.html', form=form)

            try:
                new_user = User(
                    username=form.username.data.strip(),
                    email=form.email.data.strip().lower(),
                    role='student',
                    is_active=True
                )
                new_user.set_password(form.password.data)
                db.session.add(new_user)
                db.session.flush()

                new_profile = StudentProfile(
                    user_id=new_user.id,
                    student_id=form.student_id.data.strip(),
                    full_name=form.full_name.data.strip(),
                    course=form.course.data.strip(),
                    phone=form.phone.data.strip(),
                    gender=form.gender.data,
                    guardian_name=form.guardian_name.data.strip() if form.guardian_name.data else None,
                    guardian_phone=form.guardian_phone.data.strip() if form.guardian_phone.data else None,
                    address=form.address.data.strip() if form.address.data else None,
                    is_active=True
                )
                db.session.add(new_profile)
                db.session.commit()

                flash('Registration successful! You can now log in with your credentials.', 'success')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                flash('An unexpected error occurred during registration. Please try again.', 'danger')

        return render_template('register.html', form=form)

    @app.route('/logout')
    def logout():
        session.clear()
        flash('You have been securely logged out.', 'info')
        return redirect(url_for('login'))

    # ----------------------------------------------------
    # Administrator Routes
    # ----------------------------------------------------
    @app.route('/admin/dashboard')
    @admin_required
    def admin_dashboard():
        total_students = StudentProfile.query.filter_by(is_active=True).count()
        all_rooms = Room.query.all()
        total_rooms = len(all_rooms)
        occupied_rooms = sum(1 for r in all_rooms if r.status in ('Partially Occupied', 'Full'))
        vacant_rooms = sum(1 for r in all_rooms if r.status == 'Vacant')
        pending_requests = RoomRequest.query.filter_by(status='Pending').count()

        # Update and check overdue bills
        all_bills = Bill.query.all()
        for b in all_bills:
            b.recalculate_status()
        db.session.commit()

        total_billed = sum(b.amount for b in all_bills)
        total_collected = sum(b.total_paid for b in all_bills)
        total_outstanding = sum(b.balance for b in all_bills if b.status != 'Paid')
        overdue_bills = sum(1 for b in all_bills if b.status == 'Overdue')

        recent_requests = RoomRequest.query.order_by(RoomRequest.request_date.desc()).limit(5).all()
        recent_payments = Payment.query.order_by(Payment.created_at.desc()).limit(5).all()

        return render_template(
            'admin/dashboard.html',
            total_students=total_students,
            total_rooms=total_rooms,
            occupied_rooms=occupied_rooms,
            vacant_rooms=vacant_rooms,
            pending_requests=pending_requests,
            total_billed=total_billed,
            total_collected=total_collected,
            total_outstanding=total_outstanding,
            overdue_bills=overdue_bills,
            recent_requests=recent_requests,
            recent_payments=recent_payments
        )

    # Admin Student Management
    @app.route('/admin/students')
    @admin_required
    def admin_students():
        search_query = request.args.get('search', '').strip()
        status_filter = request.args.get('status', 'all')

        query = StudentProfile.query.join(User)

        if search_query:
            query = query.filter(
                (StudentProfile.full_name.ilike(f'%{search_query}%')) |
                (StudentProfile.student_id.ilike(f'%{search_query}%')) |
                (User.username.ilike(f'%{search_query}%'))
            )

        if status_filter == 'active':
            query = query.filter(StudentProfile.is_active == True)
        elif status_filter == 'inactive':
            query = query.filter(StudentProfile.is_active == False)

        students = query.order_by(StudentProfile.id.desc()).all()
        return render_template('admin/students.html', students=students, search=search_query, status_filter=status_filter)

    @app.route('/admin/students/add', methods=['GET', 'POST'])
    @admin_required
    def admin_add_student():
        form = AdminStudentForm()
        if form.validate_on_submit():
            if not form.password.data:
                flash('Password is required when creating a new student account.', 'danger')
                return render_template('admin/student_form.html', form=form, title="Add New Student")

            if User.query.filter_by(username=form.username.data.strip()).first():
                flash('Username already exists.', 'danger')
                return render_template('admin/student_form.html', form=form, title="Add New Student")

            if User.query.filter_by(email=form.email.data.strip().lower()).first():
                flash('Email already registered.', 'danger')
                return render_template('admin/student_form.html', form=form, title="Add New Student")

            if StudentProfile.query.filter_by(student_id=form.student_id.data.strip()).first():
                flash('Student ID/Roll number already exists.', 'danger')
                return render_template('admin/student_form.html', form=form, title="Add New Student")

            try:
                user = User(
                    username=form.username.data.strip(),
                    email=form.email.data.strip().lower(),
                    role='student',
                    is_active=form.is_active.data
                )
                user.set_password(form.password.data)
                db.session.add(user)
                db.session.flush()

                profile = StudentProfile(
                    user_id=user.id,
                    student_id=form.student_id.data.strip(),
                    full_name=form.full_name.data.strip(),
                    course=form.course.data.strip(),
                    phone=form.phone.data.strip(),
                    gender=form.gender.data,
                    guardian_name=form.guardian_name.data.strip() if form.guardian_name.data else None,
                    guardian_phone=form.guardian_phone.data.strip() if form.guardian_phone.data else None,
                    address=form.address.data.strip() if form.address.data else None,
                    is_active=form.is_active.data
                )
                db.session.add(profile)
                db.session.commit()

                flash(f'Student {profile.full_name} ({profile.student_id}) added successfully.', 'success')
                return redirect(url_for('admin_students'))
            except Exception as e:
                db.session.rollback()
                flash('Failed to add student. Please verify fields and try again.', 'danger')

        return render_template('admin/student_form.html', form=form, title="Add New Student")

    @app.route('/admin/students/<int:id>/edit', methods=['GET', 'POST'])
    @admin_required
    def admin_edit_student(id):
        profile = StudentProfile.query.get_or_404(id)
        user = profile.user

        form = AdminStudentForm(obj=profile)
        if request.method == 'GET':
            form.username.data = user.username
            form.email.data = user.email
            form.is_active.data = profile.is_active

        if form.validate_on_submit():
            # Check unique username/email if changed
            existing_u = User.query.filter(User.username == form.username.data.strip(), User.id != user.id).first()
            if existing_u:
                flash('Username is already taken by another user.', 'danger')
                return render_template('admin/student_form.html', form=form, title="Edit Student", profile=profile)

            existing_e = User.query.filter(User.email == form.email.data.strip().lower(), User.id != user.id).first()
            if existing_e:
                flash('Email is already taken by another user.', 'danger')
                return render_template('admin/student_form.html', form=form, title="Edit Student", profile=profile)

            existing_sid = StudentProfile.query.filter(StudentProfile.student_id == form.student_id.data.strip(), StudentProfile.id != profile.id).first()
            if existing_sid:
                flash('Student ID is already assigned to another student.', 'danger')
                return render_template('admin/student_form.html', form=form, title="Edit Student", profile=profile)

            try:
                user.username = form.username.data.strip()
                user.email = form.email.data.strip().lower()
                user.is_active = form.is_active.data
                if form.password.data:
                    user.set_password(form.password.data)

                profile.student_id = form.student_id.data.strip()
                profile.full_name = form.full_name.data.strip()
                profile.course = form.course.data.strip()
                profile.phone = form.phone.data.strip()
                profile.gender = form.gender.data
                profile.guardian_name = form.guardian_name.data.strip() if form.guardian_name.data else None
                profile.guardian_phone = form.guardian_phone.data.strip() if form.guardian_phone.data else None
                profile.address = form.address.data.strip() if form.address.data else None
                profile.is_active = form.is_active.data

                db.session.commit()
                flash('Student details updated successfully.', 'success')
                return redirect(url_for('admin_students'))
            except Exception as e:
                db.session.rollback()
                flash('Error updating student profile.', 'danger')

        return render_template('admin/student_form.html', form=form, title="Edit Student", profile=profile)

    @app.route('/admin/students/<int:id>/view')
    @admin_required
    def admin_view_student(id):
        profile = StudentProfile.query.get_or_404(id)
        allocations = RoomAllocation.query.filter_by(student_id=id).order_by(RoomAllocation.id.desc()).all()
        bills = Bill.query.filter_by(student_id=id).order_by(Bill.id.desc()).all()
        for b in bills:
            b.recalculate_status()
        db.session.commit()
        return render_template('admin/student_view.html', student=profile, allocations=allocations, bills=bills)

    @app.route('/admin/students/<int:id>/toggle-status', methods=['POST'])
    @admin_required
    def admin_toggle_student_status(id):
        profile = StudentProfile.query.get_or_404(id)
        profile.is_active = not profile.is_active
        profile.user.is_active = profile.is_active
        db.session.commit()
        state = "activated" if profile.is_active else "deactivated"
        flash(f'Student {profile.full_name} has been {state}.', 'info')
        return redirect(url_for('admin_students'))

    @app.route('/admin/students/<int:id>/delete', methods=['POST'])
    @admin_required
    def admin_delete_student(id):
        profile = StudentProfile.query.get_or_404(id)
        # Safety check: if student has bills or payment history, prevent deletion to preserve financial records
        if profile.bills:
            flash('Cannot delete student with existing billing and financial records. Deactivate the student account instead to maintain audit integrity.', 'warning')
            return redirect(url_for('admin_students'))

        if profile.active_allocation:
            flash('Cannot delete student with an active room allocation. Please check out the student first.', 'warning')
            return redirect(url_for('admin_students'))

        try:
            user = profile.user
            db.session.delete(user)
            db.session.commit()
            flash('Student account deleted safely.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Unable to delete student. Foreign key constraints exist.', 'danger')

        return redirect(url_for('admin_students'))

    # Admin Room Management
    @app.route('/admin/rooms')
    @admin_required
    def admin_rooms():
        status_filter = request.args.get('status', 'all')
        rooms = Room.query.order_by(Room.room_number.asc()).all()

        if status_filter == 'vacant':
            rooms = [r for r in rooms if r.status == 'Vacant']
        elif status_filter == 'partially_occupied':
            rooms = [r for r in rooms if r.status == 'Partially Occupied']
        elif status_filter == 'full':
            rooms = [r for r in rooms if r.status == 'Full']

        return render_template('admin/rooms.html', rooms=rooms, status_filter=status_filter)

    @app.route('/admin/rooms/add', methods=['GET', 'POST'])
    @admin_required
    def admin_add_room():
        form = RoomForm()
        if form.validate_on_submit():
            rn = form.room_number.data.strip()
            if Room.query.filter_by(room_number=rn).first():
                flash(f'Room {rn} already exists. Duplicate room numbers are not allowed.', 'danger')
                return render_template('admin/room_form.html', form=form, title="Add New Room")

            room = Room(
                room_number=rn,
                room_type=form.room_type.data,
                capacity=form.capacity.data,
                monthly_rent=form.monthly_rent.data,
                description=form.description.data.strip() if form.description.data else None,
                is_available=form.is_available.data
            )
            db.session.add(room)
            db.session.commit()
            flash(f'Room {room.room_number} added successfully.', 'success')
            return redirect(url_for('admin_rooms'))

        return render_template('admin/room_form.html', form=form, title="Add New Room")

    @app.route('/admin/rooms/<int:id>/edit', methods=['GET', 'POST'])
    @admin_required
    def admin_edit_room(id):
        room = Room.query.get_or_404(id)
        form = RoomForm(obj=room)

        if form.validate_on_submit():
            rn = form.room_number.data.strip()
            dup = Room.query.filter(Room.room_number == rn, Room.id != room.id).first()
            if dup:
                flash(f'Room number {rn} is already taken by another room.', 'danger')
                return render_template('admin/room_form.html', form=form, title="Edit Room", room=room)

            # Prevent reducing capacity below current active occupancy
            if form.capacity.data < room.current_occupancy:
                flash(f'Cannot set capacity to {form.capacity.data}. Room currently has {room.current_occupancy} active occupant(s).', 'danger')
                return render_template('admin/room_form.html', form=form, title="Edit Room", room=room)

            room.room_number = rn
            room.room_type = form.room_type.data
            room.capacity = form.capacity.data
            room.monthly_rent = form.monthly_rent.data
            room.description = form.description.data.strip() if form.description.data else None
            room.is_available = form.is_available.data

            db.session.commit()
            flash(f'Room {room.room_number} updated successfully.', 'success')
            return redirect(url_for('admin_rooms'))

        return render_template('admin/room_form.html', form=form, title="Edit Room", room=room)

    @app.route('/admin/rooms/<int:id>/delete', methods=['POST'])
    @admin_required
    def admin_delete_room(id):
        room = Room.query.get_or_404(id)
        if room.current_occupancy > 0:
            flash(f'Cannot delete Room {room.room_number} because it has active student allocations.', 'danger')
            return redirect(url_for('admin_rooms'))

        if room.allocations:
            flash(f'Room {room.room_number} has historical allocation records. Set it to unavailable instead of deleting.', 'warning')
            return redirect(url_for('admin_rooms'))

        try:
            db.session.delete(room)
            db.session.commit()
            flash(f'Room {room.room_number} deleted successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash('Error deleting room due to associated records.', 'danger')

        return redirect(url_for('admin_rooms'))

    # Admin Room Requests & Allocation Management
    @app.route('/admin/requests')
    @admin_required
    def admin_requests():
        status_filter = request.args.get('status', 'Pending')
        query = RoomRequest.query
        if status_filter != 'all':
            query = query.filter_by(status=status_filter)
        requests = query.order_by(RoomRequest.request_date.desc()).all()
        return render_template('admin/requests.html', requests=requests, status_filter=status_filter)

    @app.route('/admin/requests/<int:id>/action', methods=['POST'])
    @admin_required
    def admin_request_action(id):
        req = RoomRequest.query.get_or_404(id)
        action = request.form.get('action')  # 'approve' or 'reject'
        remarks = request.form.get('remarks', '').strip()

        if action == 'approve':
            # Check if student already has active allocation
            if req.student.active_allocation:
                flash(f'Student {req.student.full_name} already has an active room allocation ({req.student.active_allocation.room.room_number}).', 'warning')
                return redirect(url_for('admin_requests'))

            req.status = 'Approved'
            req.remarks = remarks or 'Request approved. Proceed to assign room.'
            req.reviewed_at = datetime.now(timezone.utc)
            req.reviewed_by = session['user_id']
            db.session.commit()
            flash(f'Room request #{req.id} approved for {req.student.full_name}. Please allocate an available room.', 'success')
            return redirect(url_for('admin_new_allocation', student_id=req.student_id, room_id=req.room_id or 0))

        elif action == 'reject':
            req.status = 'Rejected'
            req.remarks = remarks or 'Request rejected by hostel administration.'
            req.reviewed_at = datetime.now(timezone.utc)
            req.reviewed_by = session['user_id']
            db.session.commit()
            flash(f'Room request #{req.id} rejected.', 'info')

        return redirect(url_for('admin_requests'))

    @app.route('/admin/allocations')
    @admin_required
    def admin_allocations():
        allocations = RoomAllocation.query.order_by(RoomAllocation.is_active.desc(), RoomAllocation.allocated_date.desc()).all()
        return render_template('admin/allocations.html', allocations=allocations)

    @app.route('/admin/allocations/new', methods=['GET', 'POST'])
    @admin_required
    def admin_new_allocation():
        form = RoomAllocationForm()

        # Populate student choices: active students who DO NOT have an active allocation
        students_without_room = [s for s in StudentProfile.query.filter_by(is_active=True).all() if not s.active_allocation]
        form.student_id.choices = [(s.id, f"{s.full_name} ({s.student_id}) - {s.course}") for s in students_without_room]

        # Populate room choices: available rooms with vacant beds
        available_rooms = [r for r in Room.query.filter_by(is_available=True).all() if not r.is_full]
        form.room_id.choices = [(r.id, f"Room {r.room_number} - {r.room_type} (Rent: ₹{r.monthly_rent:,.2f}) - {r.available_beds} beds left") for r in available_rooms]

        # Query param pre-fills
        pre_student_id = request.args.get('student_id', type=int)
        pre_room_id = request.args.get('room_id', type=int)
        if request.method == 'GET':
            if pre_student_id:
                form.student_id.data = pre_student_id
            if pre_room_id and pre_room_id > 0:
                form.room_id.data = pre_room_id
                r = db.session.get(Room, pre_room_id)
                if r:
                    form.monthly_rent.data = r.monthly_rent

        if form.validate_on_submit():
            student = StudentProfile.query.get_or_404(form.student_id.data)
            room = Room.query.get_or_404(form.room_id.data)

            # Rule 1: Student cannot have multiple active room allocations
            if student.active_allocation:
                flash(f'{student.full_name} already has an active allocation in Room {student.active_allocation.room.room_number}.', 'danger')
                return render_template('admin/allocation_form.html', form=form, title="Allocate Room")

            # Rule 2: Room cannot be allocated beyond its capacity
            if room.is_full:
                flash(f'Room {room.room_number} is already full (Capacity: {room.capacity}). Allocation prevented.', 'danger')
                return render_template('admin/allocation_form.html', form=form, title="Allocate Room")

            allocation = RoomAllocation(
                student_id=student.id,
                room_id=room.id,
                allocated_date=form.allocated_date.data,
                monthly_rent=form.monthly_rent.data,
                notes=form.notes.data.strip() if form.notes.data else None,
                is_active=True
            )
            db.session.add(allocation)

            # Update any pending room requests for this student to Approved
            pending_reqs = RoomRequest.query.filter_by(student_id=student.id, status='Pending').all()
            for pr in pending_reqs:
                pr.status = 'Approved'
                pr.room_id = room.id
                pr.reviewed_at = datetime.now(timezone.utc)
                pr.reviewed_by = session['user_id']
                pr.remarks = f'Allocated to Room {room.room_number}'

            db.session.commit()
            flash(f'Room {room.room_number} successfully allocated to {student.full_name}.', 'success')
            return redirect(url_for('admin_allocations'))

        return render_template('admin/allocation_form.html', form=form, title="Allocate Room")

    @app.route('/admin/allocations/<int:id>/checkout', methods=['POST'])
    @admin_required
    def admin_checkout_allocation(id):
        allocation = RoomAllocation.query.get_or_404(id)
        if not allocation.is_active:
            flash('Allocation is already checked out.', 'warning')
            return redirect(url_for('admin_allocations'))

        allocation.is_active = False
        allocation.checkout_date = date.today()
        db.session.commit()
        flash(f'Student {allocation.student.full_name} checked out from Room {allocation.room.room_number}.', 'success')
        return redirect(url_for('admin_allocations'))

    @app.route('/admin/allocations/<int:id>/change-room', methods=['GET', 'POST'])
    @admin_required
    def admin_change_room(id):
        current_alloc = RoomAllocation.query.get_or_404(id)
        if not current_alloc.is_active:
            flash('Cannot change room for an inactive allocation.', 'warning')
            return redirect(url_for('admin_allocations'))

        available_rooms = [r for r in Room.query.filter_by(is_available=True).all() if not r.is_full and r.id != current_alloc.room_id]

        if request.method == 'POST':
            new_room_id = request.form.get('new_room_id', type=int)
            new_rent = request.form.get('monthly_rent', type=float)
            notes = request.form.get('notes', '').strip()

            new_room = Room.query.get_or_404(new_room_id)
            if new_room.is_full:
                flash(f'Room {new_room.room_number} is full.', 'danger')
                return render_template('admin/change_room.html', alloc=current_alloc, rooms=available_rooms)

            # End current allocation
            current_alloc.is_active = False
            current_alloc.checkout_date = date.today()

            # Create new allocation
            new_alloc = RoomAllocation(
                student_id=current_alloc.student_id,
                room_id=new_room.id,
                allocated_date=date.today(),
                monthly_rent=new_rent if new_rent is not None else new_room.monthly_rent,
                notes=f"Transferred from Room {current_alloc.room.room_number}. {notes}".strip(),
                is_active=True
            )
            db.session.add(new_alloc)
            db.session.commit()

            flash(f'Student {current_alloc.student.full_name} successfully transferred to Room {new_room.room_number}.', 'success')
            return redirect(url_for('admin_allocations'))

        return render_template('admin/change_room.html', alloc=current_alloc, rooms=available_rooms)

    # Admin Fee & Bill Management
    @app.route('/admin/fees')
    @admin_required
    def admin_fees():
        student_query = request.args.get('student', '').strip()
        fee_type = request.args.get('fee_type', 'all')
        status = request.args.get('status', 'all')
        billing_period = request.args.get('period', '').strip()

        # Recalculate status for all bills before rendering
        all_bills = Bill.query.all()
        for b in all_bills:
            b.recalculate_status()
        db.session.commit()

        query = Bill.query.join(StudentProfile)

        if student_query:
            query = query.filter(
                (StudentProfile.full_name.ilike(f'%{student_query}%')) |
                (StudentProfile.student_id.ilike(f'%{student_query}%')) |
                (Bill.bill_number.ilike(f'%{student_query}%'))
            )

        if fee_type != 'all':
            query = query.filter(Bill.fee_type == fee_type)

        if status != 'all':
            query = query.filter(Bill.status == status)

        if billing_period:
            query = query.filter(Bill.billing_period.ilike(f'%{billing_period}%'))

        bills = query.order_by(Bill.id.desc()).all()

        total_billed = sum(b.amount for b in all_bills)
        total_collected = sum(b.total_paid for b in all_bills)
        pending_balance = sum(b.balance for b in all_bills if b.status != 'Paid')
        overdue_count = sum(1 for b in all_bills if b.status == 'Overdue')

        return render_template(
            'admin/fees.html',
            bills=bills,
            total_billed=total_billed,
            total_collected=total_collected,
            pending_balance=pending_balance,
            overdue_count=overdue_count,
            student_query=student_query,
            selected_fee_type=fee_type,
            selected_status=status,
            selected_period=billing_period
        )

    @app.route('/admin/fees/generate', methods=['GET', 'POST'])
    @admin_required
    def admin_generate_bill():
        form = BillForm()
        # Populate student choices
        active_students = StudentProfile.query.filter_by(is_active=True).order_by(StudentProfile.full_name.asc()).all()
        form.student_id.choices = [(0, '-- Select Student --')] + [(s.id, f"{s.full_name} ({s.student_id}) - Room: {s.current_room.room_number if s.current_room else 'None'}") for s in active_students]

        if form.validate_on_submit():
            target = form.target.data
            fee_type = form.fee_type.data
            period = form.billing_period.data.strip()
            amount = form.amount.data
            due_date = form.due_date.data
            desc = form.description.data.strip() if form.description.data else None

            created_count = 0
            skipped_duplicates = 0

            if target == 'all_allocated':
                # Bill all students who currently have an active room allocation
                allocated_students = [s for s in active_students if s.active_allocation]
                if not allocated_students:
                    flash('No students currently have active room allocations.', 'warning')
                    return render_template('admin/bill_form.html', form=form)

                for st in allocated_students:
                    # Duplicate check: student_id + fee_type + billing_period
                    existing = Bill.query.filter_by(student_id=st.id, fee_type=fee_type, billing_period=period).first()
                    if existing:
                        skipped_duplicates += 1
                        continue

                    # If fee_type is Hostel Rent and amount was left at default, we can optionally use allocated rent
                    bill_amount = st.active_allocation.monthly_rent if (fee_type == 'Hostel Rent' and amount == 0) else amount
                    bill_num = f"BIL-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}-{uuid.uuid4().hex[:4].upper()}-{st.id}"
                    bill = Bill(
                        bill_number=bill_num,
                        student_id=st.id,
                        fee_type=fee_type,
                        billing_period=period,
                        amount=bill_amount,
                        due_date=due_date,
                        description=desc or f"{fee_type} for {period}",
                        status='Pending'
                    )
                    db.session.add(bill)
                    created_count += 1

                db.session.commit()
                flash(f'Bulk billing completed: {created_count} bill(s) generated. {skipped_duplicates} duplicate(s) skipped.', 'success')
                return redirect(url_for('admin_fees'))

            else:
                # Single student billing
                student_id = form.student_id.data
                if not student_id or student_id == 0:
                    flash('Please select a student for single billing.', 'danger')
                    return render_template('admin/bill_form.html', form=form)

                st = StudentProfile.query.get_or_404(student_id)
                # Duplicate prevention check
                existing = Bill.query.filter_by(student_id=st.id, fee_type=fee_type, billing_period=period).first()
                if existing:
                    flash(f'A bill for {st.full_name} for "{fee_type}" in period "{period}" already exists (Bill #{existing.bill_number}). Duplicate monthly bills are prevented.', 'danger')
                    return render_template('admin/bill_form.html', form=form)

                bill_num = f"BIL-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M')}-{uuid.uuid4().hex[:4].upper()}-{st.id}"
                bill = Bill(
                    bill_number=bill_num,
                    student_id=st.id,
                    fee_type=fee_type,
                    billing_period=period,
                    amount=amount,
                    due_date=due_date,
                    description=desc,
                    status='Pending'
                )
                db.session.add(bill)
                db.session.commit()
                flash(f'Bill {bill.bill_number} generated successfully for {st.full_name}.', 'success')
                return redirect(url_for('admin_fees'))

        return render_template('admin/bill_form.html', form=form)

    @app.route('/admin/fees/<int:id>/view')
    @admin_required
    def admin_view_bill(id):
        bill = Bill.query.get_or_404(id)
        bill.recalculate_status()
        db.session.commit()
        return render_template('admin/bill_view.html', bill=bill)

    @app.route('/admin/fees/<int:id>/edit', methods=['GET', 'POST'])
    @admin_required
    def admin_edit_bill(id):
        bill = Bill.query.get_or_404(id)
        if bill.payments:
            flash('Cannot edit a bill that already has recorded payments. Record a refund or adjustment note instead.', 'warning')
            return redirect(url_for('admin_view_bill', id=id))

        if request.method == 'POST':
            amount = request.form.get('amount', type=float)
            due_date_str = request.form.get('due_date')
            description = request.form.get('description', '').strip()

            if not amount or amount <= 0:
                flash('Please enter a valid bill amount.', 'danger')
                return render_template('admin/bill_edit.html', bill=bill)

            bill.amount = amount
            if due_date_str:
                bill.due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
            bill.description = description
            bill.recalculate_status()
            db.session.commit()
            flash(f'Bill #{bill.bill_number} updated successfully.', 'success')
            return redirect(url_for('admin_view_bill', id=id))

        return render_template('admin/bill_edit.html', bill=bill)

    @app.route('/admin/fees/<int:id>/cancel', methods=['POST'])
    @admin_required
    def admin_cancel_bill(id):
        bill = Bill.query.get_or_404(id)
        if bill.payments:
            flash('Cannot delete or cancel a bill with recorded payment receipts. Financial records must be preserved.', 'danger')
            return redirect(url_for('admin_view_bill', id=id))

        try:
            db.session.delete(bill)
            db.session.commit()
            flash(f'Bill #{bill.bill_number} cancelled safely.', 'info')
        except Exception as e:
            db.session.rollback()
            flash('Failed to cancel bill.', 'danger')

        return redirect(url_for('admin_fees'))

    @app.route('/admin/fees/<int:id>/payment', methods=['GET', 'POST'])
    @admin_required
    def admin_record_payment(id):
        bill = Bill.query.get_or_404(id)
        bill.recalculate_status()
        if bill.balance <= 0.0:
            flash(f'Bill #{bill.bill_number} is already fully paid.', 'info')
            return redirect(url_for('admin_view_bill', id=id))

        form = PaymentForm()
        if request.method == 'GET':
            form.amount.data = bill.balance

        if form.validate_on_submit():
            pay_amt = round(form.amount.data, 2)
            if pay_amt <= 0:
                flash('Payment amount must be greater than zero.', 'danger')
                return render_template('admin/payment_form.html', form=form, bill=bill)

            if pay_amt > bill.balance:
                flash(f'Payment amount (₹{pay_amt:,.2f}) cannot exceed outstanding balance (₹{bill.balance:,.2f}).', 'danger')
                return render_template('admin/payment_form.html', form=form, bill=bill)

            rec_num = f"REC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:4].upper()}-{bill.id}"
            payment = Payment(
                receipt_number=rec_num,
                bill_id=bill.id,
                amount=pay_amt,
                payment_date=form.payment_date.data,
                payment_mode=form.payment_mode.data,
                reference_note=form.reference_note.data.strip() if form.reference_note.data else None,
                recorded_by=session['user_id']
            )
            db.session.add(payment)
            db.session.flush()

            # Recalculate bill status
            bill.recalculate_status()
            db.session.commit()

            flash(f'Payment of ₹{pay_amt:,.2f} recorded successfully (Receipt: {rec_num}). Bill status: {bill.status}.', 'success')
            return redirect(url_for('admin_view_bill', id=id))

        return render_template('admin/payment_form.html', form=form, bill=bill)

    # ----------------------------------------------------
    # Student Routes
    # ----------------------------------------------------
    @app.route('/student/dashboard')
    @student_required
    def student_dashboard():
        user = db.session.get(User, session['user_id'])
        profile = user.student_profile
        if not profile:
            flash('Student profile not found. Please contact administration.', 'danger')
            return redirect(url_for('logout'))

        active_alloc = profile.active_allocation
        room_requests = RoomRequest.query.filter_by(student_id=profile.id).order_by(RoomRequest.request_date.desc()).all()
        recent_bills = Bill.query.filter_by(student_id=profile.id).order_by(Bill.id.desc()).limit(5).all()
        for b in recent_bills:
            b.recalculate_status()
        db.session.commit()

        total_outstanding = profile.total_outstanding
        return render_template(
            'student/dashboard.html',
            profile=profile,
            active_alloc=active_alloc,
            room_requests=room_requests,
            recent_bills=recent_bills,
            total_outstanding=total_outstanding
        )

    @app.route('/student/profile', methods=['GET', 'POST'])
    @student_required
    def student_profile():
        user = db.session.get(User, session['user_id'])
        profile = user.student_profile
        form = StudentProfileForm(obj=profile)

        if form.validate_on_submit():
            profile.full_name = form.full_name.data.strip()
            profile.phone = form.phone.data.strip()
            profile.guardian_name = form.guardian_name.data.strip() if form.guardian_name.data else None
            profile.guardian_phone = form.guardian_phone.data.strip() if form.guardian_phone.data else None
            profile.address = form.address.data.strip() if form.address.data else None

            db.session.commit()
            flash('Profile updated successfully.', 'success')
            return redirect(url_for('student_profile'))

        return render_template('student/profile.html', form=form, profile=profile)

    @app.route('/student/change-password', methods=['GET', 'POST'])
    @student_required
    def student_change_password():
        user = db.session.get(User, session['user_id'])
        form = ChangePasswordForm()

        if form.validate_on_submit():
            if not user.check_password(form.current_password.data):
                flash('Current password is incorrect.', 'danger')
                return render_template('student/change_password.html', form=form)

            user.set_password(form.new_password.data)
            db.session.commit()
            flash('Password changed successfully. Please keep it safe.', 'success')
            return redirect(url_for('student_dashboard'))

        return render_template('student/change_password.html', form=form)

    @app.route('/student/rooms')
    @student_required
    def student_rooms():
        rooms = Room.query.filter_by(is_available=True).order_by(Room.room_number.asc()).all()
        return render_template('student/rooms.html', rooms=rooms)

    @app.route('/student/request-room', methods=['GET', 'POST'])
    @student_required
    def student_request_room():
        user = db.session.get(User, session['user_id'])
        profile = user.student_profile

        if profile.active_allocation:
            flash(f'You are already allocated to Room {profile.active_allocation.room.room_number}. You cannot submit a new room request.', 'warning')
            return redirect(url_for('student_dashboard'))

        existing_pending = RoomRequest.query.filter_by(student_id=profile.id, status='Pending').first()
        if existing_pending:
            flash('You already have a pending room request. Please wait for hostel administration to review it.', 'info')
            return redirect(url_for('student_dashboard'))

        form = RoomRequestForm()
        available_rooms = Room.query.filter_by(is_available=True).all()
        form.room_id.choices = [(0, '-- Any Available Room --')] + [(r.id, f"Room {r.room_number} ({r.room_type} - ₹{r.monthly_rent:,.2f})") for r in available_rooms]

        # Check pre-selected room from query param
        pre_room_id = request.args.get('room_id', type=int)
        if request.method == 'GET' and pre_room_id:
            form.room_id.data = pre_room_id

        if form.validate_on_submit():
            chosen_room_id = form.room_id.data if form.room_id.data and form.room_id.data > 0 else None
            room_req = RoomRequest(
                student_id=profile.id,
                room_id=chosen_room_id,
                remarks=form.remarks.data.strip() if form.remarks.data else None,
                status='Pending'
            )
            db.session.add(room_req)
            db.session.commit()
            flash('Your room request has been submitted successfully! Check dashboard for updates.', 'success')
            return redirect(url_for('student_dashboard'))

        return render_template('student/request_room.html', form=form)

    @app.route('/student/allocation')
    @student_required
    def student_allocation():
        user = db.session.get(User, session['user_id'])
        profile = user.student_profile
        active_alloc = profile.active_allocation

        roommates = []
        if active_alloc:
            roommates = [
                a.student for a in active_alloc.room.allocations 
                if a.is_active and a.student_id != profile.id
            ]

        return render_template('student/allocation.html', alloc=active_alloc, roommates=roommates)

    @app.route('/student/bills')
    @student_required
    def student_bills():
        user = db.session.get(User, session['user_id'])
        profile = user.student_profile
        bills = Bill.query.filter_by(student_id=profile.id).order_by(Bill.id.desc()).all()
        for b in bills:
            b.recalculate_status()
        db.session.commit()
        return render_template('student/bills.html', bills=bills, total_outstanding=profile.total_outstanding)

    @app.route('/student/bills/<int:id>')
    @student_required
    def student_view_bill(id):
        user = db.session.get(User, session['user_id'])
        profile = user.student_profile
        bill = Bill.query.get_or_404(id)

        # Enforce student privacy and access restriction
        if bill.student_id != profile.id:
            abort(403)

        bill.recalculate_status()
        db.session.commit()
        return render_template('student/bill_view.html', bill=bill)

    @app.route('/student/payments')
    @student_required
    def student_payments():
        user = db.session.get(User, session['user_id'])
        profile = user.student_profile
        # Fetch payments belonging to this student's bills
        payments = Payment.query.join(Bill).filter(Bill.student_id == profile.id).order_by(Payment.payment_date.desc()).all()
        return render_template('student/payments.html', payments=payments)

    return app


app = create_app()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host='0.0.0.0', port=5000, debug=True)
