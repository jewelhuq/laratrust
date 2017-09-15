<?php

namespace Laratrust\Test;

use Mockery as m;
use Laratrust\Tests\Models\Role;
use Laratrust\Tests\Models\Team;
use Laratrust\Tests\Models\User;
use Illuminate\Support\Facades\Config;
use Laratrust\Tests\LaratrustTestCase;
use Laratrust\Tests\Models\Permission;

class LaratrustUserTest extends LaratrustTestCase
{
    protected $user;

    public function setUp()
    {
        parent::setUp();

        $this->migrate();
        $this->user = User::create(['name' => 'test', 'email' => 'test@test.com']);

        $this->app['config']->set('laratrust.use_teams', true);
    }

    public function testRolesRelationship()
    {
        /*
        |------------------------------------------------------------
        | Assertion
        |------------------------------------------------------------
        */
        $this->app['config']->set('laratrust.use_teams', false);
        $this->assertInstanceOf(
            'Illuminate\Database\Eloquent\Relations\MorphToMany',
            $this->user->roles()
        );

        $this->app['config']->set('laratrust.use_teams', true);
        $this->assertInstanceOf(
            'Illuminate\Database\Eloquent\Relations\MorphToMany',
            $this->user->roles()
        );
    }

    public function testPermissionsRelationship()
    {
        /*
        |------------------------------------------------------------
        | Assertion
        |------------------------------------------------------------
        */
        $this->app['config']->set('laratrust.use_teams', false);
        $this->assertInstanceOf(
            'Illuminate\Database\Eloquent\Relations\MorphToMany',
            $this->user->permissions()
        );

        $this->app['config']->set('laratrust.use_teams', true);
        $this->assertInstanceOf(
            'Illuminate\Database\Eloquent\Relations\MorphToMany',
            $this->user->permissions()
        );
    }
    public function testHasRole()
    {
        /*
        |------------------------------------------------------------
        | Set
        |------------------------------------------------------------
        */
        $team = Team::create(['name' => 'team_a']);
        $roles = [
            Role::create(['name' => 'role_a'])->id => ['team_id' => null],
            Role::create(['name' => 'role_b'])->id => ['team_id' => null],
            Role::create(['name' => 'role_c'])->id => ['team_id' => $team->id ]
        ];
        $this->app['config']->set('laratrust.use_teams', true);
        $this->user->roles()->attach($roles);

        /*
        |------------------------------------------------------------
        | Assertion
        |------------------------------------------------------------
        */
        $this->assertTrue($this->user->hasRole([]));
        $this->assertTrue($this->user->hasRole('role_a'));
        $this->assertTrue($this->user->hasRole('role_b'));
        $this->assertTrue($this->user->hasRole('role_c'));
        $this->app['config']->set('laratrust.teams_strict_check', true);
        $this->assertFalse($this->user->hasRole('role_c'));
        $this->app['config']->set('laratrust.teams_strict_check', false);
        $this->assertTrue($this->user->hasRole('role_c', 'team_a'));
        $this->assertFalse($this->user->hasRole('role_a', 'team_a'));

        $this->assertTrue($this->user->hasRole('role_a|role_b'));
        $this->assertTrue($this->user->hasRole(['role_a', 'role_b']));
        $this->assertTrue($this->user->hasRole(['role_a', 'role_c']));
        $this->assertTrue($this->user->hasRole(['role_a', 'role_c'], 'team_a'));
        $this->assertFalse($this->user->hasRole(['role_a', 'role_c'], 'team_a', true));
        $this->assertTrue($this->user->hasRole(['role_a', 'role_c'], true));
        $this->assertFalse($this->user->hasRole(['role_c', 'role_d'], true));

        $this->app['config']->set('laratrust.use_teams', false);
        $this->assertTrue($this->user->hasRole(['role_a', 'role_c'], 'team_a'));
        $this->assertFalse($this->user->hasRole(['role_c', 'role_d'], true));
    }

    public function testHasPermission()
    {
        /*
        |------------------------------------------------------------
        | Set
        |------------------------------------------------------------
        */
        $team = Team::create(['name' => 'team_a']);

        $roleA = Role::create(['name' => 'role_a'])
            ->attachPermission(Permission::create(['name' => 'permission_a']));
        $roleB = Role::create(['name' => 'role_b'])
            ->attachPermission(Permission::create(['name' => 'permission_b']));

        $this->user->roles()->attach([
            $roleA->id => ['team_id' => null],
            $roleB->id => ['team_id' => $team->id ]
        ]);

        $this->user->permissions()->attach([
            Permission::create(['name' => 'permission_c'])->id => ['team_id' => $team->id ],
            Permission::create(['name' => 'permission_d'])->id => ['team_id' => null],
        ]);

        /*
        |------------------------------------------------------------
        | Assertion
        |------------------------------------------------------------
        */
        $this->assertTrue($this->user->hasPermission([]));
        $this->assertTrue($this->user->hasPermission('permission_a'));
        $this->assertTrue($this->user->hasPermission('permission_b', 'team_a'));
        $this->assertTrue($this->user->hasPermission('permission_c', 'team_a'));
        $this->assertTrue($this->user->hasPermission('permission_d'));
        $this->assertFalse($this->user->hasPermission('permission_e'));

        $this->assertTrue($this->user->hasPermission(['permission_a', 'permission_b', 'permission_c', 'permission_d', 'permission_e']));
        $this->assertTrue($this->user->hasPermission('permission_a|permission_b|permission_c|permission_d|permission_e'));
        $this->assertTrue($this->user->hasPermission(['permission_a', 'permission_d'], true));
        $this->assertTrue($this->user->hasPermission(['permission_a', 'permission_b', 'permission_d'], true));
        $this->assertFalse($this->user->hasPermission(['permission_a', 'permission_b', 'permission_d'], 'team_a', true));
        $this->assertFalse($this->user->hasPermission(['permission_a', 'permission_b', 'permission_e'], true));
        $this->assertFalse($this->user->hasPermission(['permission_e', 'permission_f']));

        $this->app['config']->set('laratrust.use_teams', false);
        $this->assertTrue($this->user->hasPermission(['permission_a', 'permission_b', 'permission_d'], 'team_a', true));
    }

    public function testCan()
    {
        /*
        |------------------------------------------------------------
        | Set
        |------------------------------------------------------------
        */
        $user = m::mock('Laratrust\Tests\Models\User')->makePartial();

        /*
        |------------------------------------------------------------
        | Expectation
        |------------------------------------------------------------
        */
        $user->shouldReceive('hasPermission')->with('manage_user', null, false)->andReturn(true)->once();

        /*
        |------------------------------------------------------------
        | Assertion
        |------------------------------------------------------------
        */
        $this->assertTrue($user->can('manage_user'));
    }

    public function testIsAbleTo()
    {
        /*
        |------------------------------------------------------------
        | Set
        |------------------------------------------------------------
        */
        $user = m::mock('Laratrust\Tests\Models\User')->makePartial();

        /*
        |------------------------------------------------------------
        | Expectation
        |------------------------------------------------------------
        */
        $user->shouldReceive('hasPermission')->with('manage_user', null, false)->andReturn(true)->once();

        /*
        |------------------------------------------------------------
        | Assertion
        |------------------------------------------------------------
        */
        $this->assertTrue($user->isAbleTo('manage_user'));
    }

    public function testHasPermissionWithPlaceholderSupport()
    {
        /*
        |------------------------------------------------------------
        | Set
        |------------------------------------------------------------
        */
        $team = Team::create(['name' => 'team_a']);

        $role = Role::create(['name' => 'role_a'])
            ->attachPermissions([
                Permission::create(['name' => 'admin.posts']),
                Permission::create(['name' => 'admin.pages']),
                Permission::create(['name' => 'admin.users']),
            ]);

        $this->user->roles()->attach($role->id);

        $this->user->permissions()->attach([
            Permission::create(['name' => 'config.things'])->id => ['team_id' => $team->id ],
            Permission::create(['name' => 'config.another_things'])->id => ['team_id' => $team->id],
        ]);

        /*
        |------------------------------------------------------------
        | Assertion
        |------------------------------------------------------------
        */
        $this->assertTrue($this->user->hasPermission('admin.posts'));
        $this->assertTrue($this->user->hasPermission('admin.pages'));
        $this->assertTrue($this->user->hasPermission('admin.users'));
        $this->assertFalse($this->user->hasPermission('admin.config', 'TeamA'));

        $this->assertTrue($this->user->hasPermission(['admin.*']));
        $this->assertTrue($this->user->hasPermission(['admin.*']));
        $this->assertTrue($this->user->hasPermission(['config.*'], 'TeamA'));
        $this->assertTrue($this->user->hasPermission(['config.*']));
        $this->assertFalse($this->user->hasPermission(['site.*']));
    }

    public function testMagicCanPermissionMethod()
    {
        /*
        |------------------------------------------------------------
        | Set
        |------------------------------------------------------------
        */
        $this->user->permissions()->attach([
            Permission::create(['name' => 'manage-user'])->id,
            Permission::create(['name' => 'manage_user'])->id,
            Permission::create(['name' => 'manageUser'])->id,
        ]);

        /*
        |------------------------------------------------------------
        | Assertion
        |------------------------------------------------------------
        */
        $this->app['config']->set('laratrust.magic_can_method_case', 'kebab_case');
        $this->assertTrue($this->user->canManageUser());

        $this->app['config']->set('laratrust.magic_can_method_case', 'snake_case');
        $this->assertTrue($this->user->canManageUser());

        $this->app['config']->set('laratrust.magic_can_method_case', 'camel_case');
        $this->assertTrue($this->user->canManageUser());
    }

    public function testAttachRole()
    {
        /*
        |------------------------------------------------------------
        | Set
        |------------------------------------------------------------
        */
        $role = Role::create(['name' => 'role_a']);
        $team = Team::create(['name' => 'team_a']);

        /*
        |------------------------------------------------------------
        | Assertion
        |------------------------------------------------------------
        */
        // Can attach role by passing an object
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $this->user->attachRole($role));
        $this->assertEquals(1, $this->user->roles()->count());
        $this->user->roles()->sync([]);
        // Can attach role by passing an id
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $this->user->attachRole($role->id));
        $this->assertEquals(1, $this->user->roles()->count());
        $this->user->roles()->sync([]);
        // Can attach role by passing an array with 'id' => $id
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $this->user->attachRole($role->toArray()));
        $this->assertEquals(1, $this->user->roles()->count());
        $this->user->roles()->sync([]);
        // Can attach role by passing the role name
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $this->user->attachRole('role_a'));
        $this->assertEquals(1, $this->user->roles()->count());
        $this->user->roles()->sync([]);
        // Can attach role by passing the role and team
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $this->user->attachRole($role, $team));
        $this->assertEquals(1, $this->user->roles()->count());
        $this->user->roles()->sync([]);
        // Can attach role by passing the role and team id
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $this->user->attachRole($role, $team->id));
        $this->assertEquals($team->id, $this->user->roles()->first()->pivot->team_id);
        $this->user->roles()->sync([]);
        // Can attach role by passing the role and team name
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $this->user->attachRole($role, 'team_a'));
        $this->assertEquals($team->id, $this->user->roles()->first()->pivot->team_id);
        $this->user->roles()->sync([]);

        $this->app['config']->set('laratrust.use_teams', false);
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $this->user->attachRole($role));
        $this->assertEquals(1, $this->user->roles()->count());
        $this->user->roles()->sync([]);

        $this->assertInstanceOf('Laratrust\Tests\Models\User', $this->user->attachRole($role, 'team_a'));
        $this->assertNull($this->user->roles()->first()->pivot->team_id);
        $this->user->roles()->sync([]);
    }

    public function testDetachRole()
    {
        /*
        |------------------------------------------------------------
        | Set
        |------------------------------------------------------------
        */
        $role = Role::create(['name' => 'role_a']);
        $this->user->roles()->attach($role->id);
        $team = Team::create(['name' => 'team_a']);

        /*
        |------------------------------------------------------------
        | Assertion
        |------------------------------------------------------------
        */
        // Can attach role by passing an object
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $this->user->detachRole($role));
        $this->assertEquals(0, $this->user->roles()->count());
        $this->user->roles()->attach($role->id);
        // Can detach role by passing an id
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $this->user->detachRole($role->id));
        $this->assertEquals(0, $this->user->roles()->count());
        $this->user->roles()->attach($role->id);
        // Can detach role by passing an array with 'id' => $id
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $this->user->detachRole($role->toArray()));
        $this->assertEquals(0, $this->user->roles()->count());
        $this->user->roles()->attach($role->id);
        // Can detach role by passing the role name
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $this->user->detachRole('role_a'));
        $this->assertEquals(0, $this->user->roles()->count());
        $this->user->roles()->attach($role->id, ['team_id' => $team->id]);
        // Can detach role by passing the role and team
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $this->user->detachRole($role, $team));
        $this->assertEquals(0, $this->user->roles()->count());
        $this->user->roles()->attach($role->id, ['team_id' => $team->id]);
        // Can detach role by passing the role and team id
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $this->user->detachRole($role, $team->id));
        $this->assertEquals(0, $this->user->roles()->count());
        $this->user->roles()->attach($role->id, ['team_id' => $team->id]);
        // Can detach role by passing the role and team name
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $this->user->detachRole($role, 'team_a'));

        $this->app['config']->set('laratrust.use_teams', false);
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $this->user->detachRole($role));
        $this->assertEquals(0, $this->user->roles()->count());
        $this->user->roles()->attach($role->id);
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $this->user->detachRole($role, 'TeamA'));
        $this->assertEquals(0, $this->user->roles()->count());
        $this->user->roles()->attach($role->id);
    }

    public function testAttachRoles()
    {
        /*
        |------------------------------------------------------------
        | Set
        |------------------------------------------------------------
        */
        $user = m::mock('Laratrust\Tests\Models\User')->makePartial();

        /*
        |------------------------------------------------------------
        | Expectation
        |------------------------------------------------------------
        */
        $user->shouldReceive('attachRole')->with(m::anyOf(1, 2, 3), m::anyOf(null, 'TeamA'))->times(6);

        /*
        |------------------------------------------------------------
        | Assertion
        |------------------------------------------------------------
        */
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $user->attachRoles([1, 2, 3]));
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $user->attachRoles([1, 2, 3], 'TeamA'));
    }

    public function testDetachRoles()
    {
        /*
        |------------------------------------------------------------
        | Set
        |------------------------------------------------------------
        */
        $user = m::mock('Laratrust\Tests\Models\User')->makePartial();

        /*
        |------------------------------------------------------------
        | Expectation
        |------------------------------------------------------------
        */
        $user->shouldReceive('roles->get')->andReturn([1, 2, 3])->once();
        $user->shouldReceive('detachRole')->with(m::anyOf(1, 2, 3), m::anyOf(null, 'TeamA'))->times(9);

        /*
        |------------------------------------------------------------
        | Assertion
        |------------------------------------------------------------
        */
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $user->detachRoles([1, 2, 3]));
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $user->detachRoles([]));
        $this->assertInstanceOf('Laratrust\Tests\Models\User', $user->detachRoles([1, 2, 3], 'TeamA'));
    }

    public function testSyncRoles()
    {

    }
}
