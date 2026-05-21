import requests
import time
import sys

BASE = 'http://127.0.0.1:5000'

admin_email = 'admin@omniflow.test'
admin_pw = 'admin123'

users = {
    'Member': {'email': 'perm_member@example.com', 'password': 'member123'},
    'Manager': {'email': 'perm_manager@example.com', 'password': 'manager123'},
    'Admin': {'email': 'perm_admin@example.com', 'password': 'adminuser123'},
}

session = requests.Session()
csrf_token = None


def wait_ready(timeout=8):
    for i in range(timeout * 2):
        try:
            r = requests.get(BASE + '/api/home/stats', timeout=1)
            if r.status_code == 200:
                return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def login(email, password):
    global csrf_token
    r = session.post(BASE + '/api/login', json={'email': email, 'password': password}, allow_redirects=False)
    if not r.ok:
        print(f'Login failed for {email}:', r.status_code, r.text)
        return False
    # fetch csrf token
    r2 = session.get(BASE + '/api/csrf')
    if r2.ok:
        csrf_token = r2.json().get('csrf_token')
    return True


def logout():
    global csrf_token
    session.post(BASE + '/api/logout', headers={'X-CSRF-Token': csrf_token} if csrf_token else {})
    csrf_token = None


def api(path, method='get', json=None):
    headers = {}
    if method.lower() in ('post', 'put', 'patch', 'delete'):
        if csrf_token:
            headers['X-CSRF-Token'] = csrf_token
    fn = getattr(session, method.lower())
    return fn(BASE + path, json=json, headers=headers, allow_redirects=False)


if not wait_ready():
    print('Server not responding at', BASE)
    sys.exit(2)

# Login admin and create test users
if not login(admin_email, admin_pw):
    sys.exit(2)
print('Admin login OK')

created_users = {}
for role, creds in users.items():
    payload = {'name': f'Test {role}', 'email': creds['email'], 'password': creds['password'], 'role': role}
    r = api('/api/settings/users', method='post', json=payload)
    if r.status_code not in (200, 201):
        print('Failed to create user', role, r.status_code, r.text)
        sys.exit(2)
    created_users[role] = r.json()
    print(f'Created user {role}:', created_users[role]['email'])

# Fetch current permissions to use as expected results
r = api('/api/settings/permissions')
if not r.ok:
    print('Failed to read permissions', r.status_code, r.text)
    sys.exit(2)
permissions = r.json()
print('Loaded permissions for roles:', list(permissions.keys()))

# Resources payload templates
templates = {
    'orders': {'client_id': 'C-1001', 'product': 'Perm Test Product', 'qty': 1, 'amount': 10},
    'clients': {'name': 'Perm Test Client', 'contact': 'Perm Tester', 'email': 'perm.client@example.com', 'phone': '555-0001', 'address': '123 Test Ln'},
    'inventory': {'name': 'Perm SKU', 'category': 'Test', 'stock': 10, 'min_stock': 2, 'unit': 'pcs'},
}

created_resources = {r: {} for r in templates}

# For each role, login and test create/update/delete for each resource
for role, creds in users.items():
    print('\n--- Testing role', role, '---')
    logout()
    if not login(creds['email'], creds['password']):
        print('Login failed for role', role)
        sys.exit(2)
    print('Logged in as', role)
    role_perms = permissions.get(role, {})
    for resource, payload in templates.items():
        res_perms = role_perms.get(resource, {})
        # CREATE
        r = api(f'/api/{resource}', method='post', json=payload)
        can_create = bool(res_perms.get('create')) or ('manager' in role.lower()) or (role.lower() == 'admin')
        if can_create:
            if r.status_code not in (200, 201):
                print(f'[FAIL] {role} should be able to CREATE {resource}:', r.status_code, r.text)
                sys.exit(2)
            print(f'[OK] {role} CREATE {resource} ->', r.status_code)
            obj = r.json()
            created_resources[resource][role] = obj.get('id')
        else:
            if r.status_code == 403:
                print(f'[OK] {role} forbidden to CREATE {resource} (403)')
            else:
                print(f'[FAIL] {role} unexpected CREATE {resource} status:', r.status_code)
                sys.exit(2)
        # UPDATE (if we have an id use it, else skip)
        obj_id = created_resources[resource].get(role)
        if obj_id:
            update_payload = {}
            if resource == 'orders':
                update_payload = {'notes': f'Updated by {role}'}
            elif resource == 'clients':
                update_payload = {'phone': '555-9999'}
            elif resource == 'inventory':
                update_payload = {'stock': 99}
            r = api(f'/api/{resource}/{obj_id}', method='put', json=update_payload)
            can_update = bool(res_perms.get('update')) or ('manager' in role.lower()) or (role.lower() == 'admin')
            if can_update:
                if r.status_code not in (200, 201):
                    print(f'[FAIL] {role} should be able to UPDATE {resource}:', r.status_code, r.text)
                    sys.exit(2)
                print(f'[OK] {role} UPDATE {resource} ->', r.status_code)
            else:
                if r.status_code == 403:
                    print(f'[OK] {role} forbidden to UPDATE {resource} (403)')
                else:
                    print(f'[FAIL] {role} unexpected UPDATE {resource} status:', r.status_code)
                    sys.exit(2)
        # DELETE
        # For delete, try deleting the created id if present; else try deleting a known resource (inventory list)
        del_id = obj_id
        if not del_id and resource == 'inventory':
            # pick an existing inventory item
            rlist = api('/api/inventory')
            if rlist.ok and rlist.json():
                del_id = rlist.json()[0]['id']
        if del_id:
            r = api(f'/api/{resource}/{del_id}', method='delete')
            can_delete = bool(res_perms.get('delete')) or ('manager' in role.lower()) or (role.lower() == 'admin')
            if can_delete:
                if r.status_code not in (200, 204):
                    print(f'[FAIL] {role} should be able to DELETE {resource}:', r.status_code, r.text)
                    sys.exit(2)
                print(f'[OK] {role} DELETE {resource} ->', r.status_code)
            else:
                if r.status_code == 403:
                    print(f'[OK] {role} forbidden to DELETE {resource} (403)')
                else:
                    print(f'[FAIL] {role} unexpected DELETE {resource} status:', r.status_code)
                    sys.exit(2)

# Cleanup: login as admin and remove created users and any resources we created
logout()
if not login(admin_email, admin_pw):
    print('Failed to relogin as admin for cleanup')
    sys.exit(2)

# remove created users
for role, info in created_users.items():
    uid = info.get('id')
    if uid:
        r = api(f'/api/settings/users/{uid}', method='delete')
        if r.status_code in (200, 204):
            print('Removed test user', role)

# remove created resources (best-effort)
for resource, by_role in created_resources.items():
    for role, rid in by_role.items():
        if not rid:
            continue
        r = api(f'/api/{resource}/{rid}', method='delete')
        if r.status_code in (200, 204):
            print('Removed resource', resource, rid)

print('\nPermission matrix tests completed successfully')
