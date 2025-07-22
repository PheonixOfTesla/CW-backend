exports.up = function(knex) {
  return knex.schema
    // Enable UUID extension
    .raw('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    
    // Users table
    .createTable('users', table => {
      table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));
      table.string('email').unique().notNullable();
      table.string('password').notNullable();
      table.string('name').notNullable();
      table.string('phone');
      table.string('address');
      table.json('roles').defaultTo('["client"]');
      table.boolean('two_factor_enabled').defaultTo(false);
      table.string('two_factor_secret');
      table.string('subscription_plan').defaultTo('basic');
      table.boolean('billing_enabled').defaultTo(false);
      table.boolean('can_train_clients').defaultTo(false);
      table.boolean('can_assign_billing').defaultTo(false);
      table.string('stripe_customer_id');
      table.string('profile_picture_url');
      table.boolean('is_online').defaultTo(false);
      table.timestamp('last_seen');
      table.json('specialization');
      table.json('client_ids').defaultTo('[]');
      table.json('specialist_ids').defaultTo('[]');
      table.timestamps(true, true);
      
      // Indexes
      table.index('email');
      table.index('created_at');
    })
    
    // Measurements table
    .createTable('measurements', table => {
      table.increments('id');
      table.uuid('client_id').references('id').inTable('users').onDelete('CASCADE');
      table.uuid('recorded_by').references('id').inTable('users');
      table.date('date').notNullable();
      table.decimal('weight', 5, 2);
      table.decimal('body_fat', 4, 2);
      table.integer('bmr');
      table.string('blood_pressure');
      table.decimal('height', 5, 2);
      table.integer('age');
      table.string('gender');
      table.string('activity_level');
      table.json('circumference').defaultTo('{}');
      table.json('caliper').defaultTo('{}');
      table.timestamps(true, true);
      
      // Indexes
      table.index(['client_id', 'date']);
      table.index('created_at');
    })
    
    // Workouts table
    .createTable('workouts', table => {
      table.increments('id');
      table.uuid('client_id').references('id').inTable('users').onDelete('CASCADE');
      table.uuid('assigned_by').references('id').inTable('users');
      table.string('name').notNullable();
      table.json('exercises').defaultTo('[]');
      table.boolean('completed').defaultTo(false);
      table.integer('mood_feedback');
      table.text('notes');
      table.date('scheduled_date');
      table.date('completed_date');
      table.integer('duration'); // minutes
      table.integer('calories_burned');
      table.string('exercise_image_url');
      table.string('youtube_link');
      table.json('template_data');
      table.timestamps(true, true);
      
      // Indexes
      table.index('client_id');
      table.index('scheduled_date');
      table.index('completed');
    })
    
    // Nutrition table
    .createTable('nutrition', table => {
      table.uuid('client_id').primary().references('id').inTable('users').onDelete('CASCADE');
      table.uuid('assigned_by').references('id').inTable('users');
      table.json('protein').defaultTo('{"target": 0, "current": 0}');
      table.json('carbs').defaultTo('{"target": 0, "current": 0}');
      table.json('fat').defaultTo('{"target": 0, "current": 0}');
      table.json('calories').defaultTo('{"target": 0, "current": 0}');
      table.json('fiber').defaultTo('{"target": 0, "current": 0}');
      table.json('water').defaultTo('{"target": 0, "current": 0}');
      table.json('meal_plan').defaultTo('{}');
      table.json('restrictions').defaultTo('[]');
      table.json('supplements').defaultTo('[]');
      table.timestamps(true, true);
    })
    
    // Goals table
    .createTable('goals', table => {
      table.increments('id');
      table.uuid('client_id').references('id').inTable('users').onDelete('CASCADE');
      table.uuid('assigned_by').references('id').inTable('users');
      table.string('name').notNullable();
      table.decimal('target', 10, 2);
      table.decimal('current', 10, 2);
      table.date('deadline');
      table.string('category');
      table.string('priority');
      table.json('milestones').defaultTo('[]');
      table.boolean('completed').defaultTo(false);
      table.date('completed_date');
      table.timestamps(true, true);
      
      // Indexes
      table.index('client_id');
      table.index('deadline');
      table.index('completed');
    })
    
    // Tests table
    .createTable('tests', table => {
      table.increments('id');
      table.uuid('client_id').references('id').inTable('users').onDelete('CASCADE');
      table.uuid('performed_by').references('id').inTable('users');
      table.string('name').notNullable();
      table.date('date').notNullable();
      table.text('results');
      table.string('category');
      table.json('attachments').defaultTo('[]');
      table.text('notes');
      table.timestamps(true, true);
      
      // Indexes
      table.index(['client_id', 'date']);
    })
    
    // Messages table
    .createTable('messages', table => {
      table.increments('id');
      table.uuid('sender_id').references('id').inTable('users').onDelete('CASCADE');
      table.uuid('recipient_id').references('id').inTable('users').onDelete('CASCADE');
      table.text('text').notNullable();
      table.boolean('read').defaultTo(false);
      table.boolean('edited').defaultTo(false);
      table.string('attachment_url');
      table.string('attachment_type');
      table.json('reactions').defaultTo('{}');
      table.uuid('reply_to_id');
      table.timestamps(true, true);
      
      // Indexes
      table.index(['sender_id', 'recipient_id']);
      table.index('created_at');
    })
    
    // Invoices table
    .createTable('invoices', table => {
      table.string('id').primary();
      table.uuid('client_id').references('id').inTable('users').onDelete('CASCADE');
      table.uuid('issued_by').references('id').inTable('users');
      table.date('date').notNullable();
      table.date('due_date');
      table.decimal('amount', 10, 2);
      table.decimal('tax', 10, 2);
      table.decimal('total', 10, 2);
      table.string('status').defaultTo('pending');
      table.text('description');
      table.json('items').defaultTo('[]');
      table.string('payment_method');
      table.string('stripe_invoice_id');
      table.string('stripe_payment_intent_id');
      table.date('paid_date');
      table.string('receipt_url');
      table.timestamps(true, true);
      
      // Indexes
      table.index('client_id');
      table.index('status');
      table.index('date');
    })
    
    // Payments table
    .createTable('payments', table => {
      table.string('id').primary();
      table.string('invoice_id').references('id').inTable('invoices');
      table.uuid('client_id').references('id').inTable('users').onDelete('CASCADE');
      table.decimal('amount', 10, 2).notNullable();
      table.date('date').notNullable();
      table.string('method');
      table.string('last4');
      table.string('brand');
      table.string('status').defaultTo('pending');
      table.string('stripe_payment_id');
      table.string('receipt');
      table.timestamps(true, true);
      
      // Indexes
      table.index('client_id');
      table.index('invoice_id');
      table.index('date');
    })
    
    // Subscriptions table
    .createTable('subscriptions', table => {
      table.string('id').primary();
      table.uuid('client_id').references('id').inTable('users').onDelete('CASCADE');
      table.uuid('specialist_id').references('id').inTable('users');
      table.string('name').notNullable();
      table.decimal('amount', 10, 2);
      table.decimal('tax', 10, 2);
      table.decimal('total', 10, 2);
      table.string('frequency').defaultTo('monthly');
      table.string('status').defaultTo('active');
      table.date('start_date').notNullable();
      table.date('next_billing_date');
      table.date('canceled_at');
      table.string('stripe_subscription_id');
      table.string('stripe_price_id');
      table.json('features').defaultTo('[]');
      table.timestamps(true, true);
      
      // Indexes
      table.index('client_id');
      table.index('status');
    })
    
    // Payment methods table
    .createTable('payment_methods', table => {
      table.string('id').primary();
      table.uuid('client_id').references('id').inTable('users').onDelete('CASCADE');
      table.string('type').defaultTo('card');
      table.string('last4');
      table.string('brand');
      table.integer('expiry_month');
      table.integer('expiry_year');
      table.boolean('is_default').defaultTo(false);
      table.string('stripe_payment_method_id');
      table.timestamps(true, true);
      
      // Indexes
      table.index('client_id');
    })
    
    // Training sessions table
    .createTable('training_sessions', table => {
      table.string('id').primary().defaultTo(knex.raw("'SESSION-' || nextval('training_sessions_seq')"));
      table.uuid('trainer_id').references('id').inTable('users');
      table.uuid('client_id').references('id').inTable('users');
      table.date('date').notNullable();
      table.time('time').notNullable();
      table.integer('duration').defaultTo(60); // minutes
      table.string('type');
      table.string('status').defaultTo('scheduled');
      table.string('location');
      table.text('notes');
      table.boolean('reminder_sent').defaultTo(false);
      table.string('zoom_link');
      table.timestamp('completed_at');
      table.text('feedback');
      table.timestamps(true, true);
      
      // Indexes
      table.index(['trainer_id', 'date']);
      table.index(['client_id', 'date']);
      table.index('status');
    })
    
    // Audit logs table
    .createTable('audit_logs', table => {
      table.increments('id');
      table.uuid('user_id').references('id').inTable('users');
      table.string('action').notNullable();
      table.string('resource');
      table.string('resource_id');
      table.text('details');
      table.string('ip_address');
      table.text('user_agent');
      table.json('metadata').defaultTo('{}');
      table.timestamp('timestamp').defaultTo(knex.fn.now());
      
      // Indexes
      table.index('user_id');
      table.index('timestamp');
      table.index('action');
      table.index(['resource', 'resource_id']);
    })
    
    // Email logs table
    .createTable('email_logs', table => {
      table.string('id').primary();
      table.string('to').notNullable();
      table.string('from');
      table.string('subject');
      table.string('template_id');
      table.string('status').defaultTo('pending');
      table.timestamp('sent_at');
      table.timestamp('opened_at');
      table.json('metadata').defaultTo('{}');
      table.timestamps(true, true);
      
      // Indexes
      table.index('to');
      table.index('status');
      table.index('sent_at');
    })
    
    // Create sequence for training sessions
    .raw('CREATE SEQUENCE IF NOT EXISTS training_sessions_seq START 1000')
    
    // Create analytics views
    .raw(`
      CREATE OR REPLACE VIEW client_metrics AS
      SELECT 
        u.id as client_id,
        u.name,
        COUNT(DISTINCT w.id) as total_workouts,
        COUNT(DISTINCT CASE WHEN w.completed THEN w.id END) as completed_workouts,
        COUNT(DISTINCT m.id) as total_measurements,
        COUNT(DISTINCT g.id) as total_goals,
        COUNT(DISTINCT CASE WHEN g.completed THEN g.id END) as completed_goals,
        MAX(w.completed_date) as last_workout_date,
        MAX(m.date) as last_measurement_date
      FROM users u
      LEFT JOIN workouts w ON w.client_id = u.id
      LEFT JOIN measurements m ON m.client_id = u.id
      LEFT JOIN goals g ON g.client_id = u.id
      WHERE '["client"]'::jsonb @> u.roles::jsonb
      GROUP BY u.id, u.name
    `);
};

exports.down = function(knex) {
  return knex.schema
    // Drop views
    .raw('DROP VIEW IF EXISTS client_metrics')
    
    // Drop sequences
    .raw('DROP SEQUENCE IF EXISTS training_sessions_seq')
    
    // Drop tables in reverse order
    .dropTableIfExists('email_logs')
    .dropTableIfExists('audit_logs')
    .dropTableIfExists('training_sessions')
    .dropTableIfExists('payment_methods')
    .dropTableIfExists('subscriptions')
    .dropTableIfExists('payments')
    .dropTableIfExists('invoices')
    .dropTableIfExists('messages')
    .dropTableIfExists('tests')
    .dropTableIfExists('goals')
    .dropTableIfExists('nutrition')
    .dropTableIfExists('workouts')
    .dropTableIfExists('measurements')
    .dropTableIfExists('users');
};