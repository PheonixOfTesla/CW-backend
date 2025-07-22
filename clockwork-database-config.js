const knex = require('knex');
const { Pool } = require('pg');

// PostgreSQL connection pool
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' 
    ? { rejectUnauthorized: false } 
    : false,
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

// Knex configuration for query building and migrations
const db = knex({
  client: 'pg',
  connection: {
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' 
      ? { rejectUnauthorized: false } 
      : false,
  },
  pool: {
    min: 2,
    max: 10,
    afterCreate: (conn, done) => {
      // Run any setup queries after connection
      conn.query('SET timezone="UTC";', (err) => {
        done(err, conn);
      });
    }
  },
  searchPath: ['public'],
  migrations: {
    directory: './migrations',
    tableName: 'knex_migrations'
  },
  seeds: {
    directory: './seeds'
  },
  // Log queries in development
  debug: process.env.NODE_ENV === 'development',
});

// Test database connection
const connectDB = async () => {
  try {
    // Test with a simple query
    await db.raw('SELECT 1+1 AS result');
    console.log('✅ PostgreSQL connected successfully');
    
    // Run migrations automatically in development
    if (process.env.NODE_ENV === 'development') {
      console.log('Running database migrations...');
      await db.migrate.latest();
      console.log('✅ Migrations completed');
    }
    
    return true;
  } catch (error) {
    console.error('❌ PostgreSQL connection failed:', error.message);
    throw error;
  }
};

// Helper function to handle transactions
const transaction = async (callback) => {
  const trx = await db.transaction();
  try {
    const result = await callback(trx);
    await trx.commit();
    return result;
  } catch (error) {
    await trx.rollback();
    throw error;
  }
};

// Utility function to check if a table exists
const tableExists = async (tableName) => {
  const result = await db.raw(`
    SELECT EXISTS (
      SELECT FROM information_schema.tables 
      WHERE table_schema = 'public' 
      AND table_name = ?
    );
  `, [tableName]);
  return result.rows[0].exists;
};

// Utility function to get table info
const getTableInfo = async (tableName) => {
  const result = await db.raw(`
    SELECT 
      column_name,
      data_type,
      is_nullable,
      column_default
    FROM information_schema.columns
    WHERE table_schema = 'public'
    AND table_name = ?
    ORDER BY ordinal_position;
  `, [tableName]);
  return result.rows;
};

// Export database instances and utilities
module.exports = {
  db,
  pool,
  connectDB,
  transaction,
  tableExists,
  getTableInfo,
  
  // Convenience methods for common queries
  findById: async (table, id) => {
    return await db(table).where({ id }).first();
  },
  
  findByEmail: async (table, email) => {
    return await db(table).where({ email }).first();
  },
  
  findAll: async (table, conditions = {}, options = {}) => {
    let query = db(table).where(conditions);
    
    if (options.orderBy) {
      query = query.orderBy(options.orderBy, options.order || 'asc');
    }
    
    if (options.limit) {
      query = query.limit(options.limit);
    }
    
    if (options.offset) {
      query = query.offset(options.offset);
    }
    
    return await query;
  },
  
  create: async (table, data) => {
    const [result] = await db(table).insert(data).returning('*');
    return result;
  },
  
  update: async (table, id, data) => {
    const [result] = await db(table)
      .where({ id })
      .update({ ...data, updated_at: new Date() })
      .returning('*');
    return result;
  },
  
  delete: async (table, id) => {
    return await db(table).where({ id }).delete();
  },
  
  // Pagination helper
  paginate: async (table, page = 1, limit = 20, conditions = {}, orderBy = 'created_at') => {
    const offset = (page - 1) * limit;
    
    const [data, [{ count }]] = await Promise.all([
      db(table)
        .where(conditions)
        .orderBy(orderBy, 'desc')
        .limit(limit)
        .offset(offset),
      db(table)
        .where(conditions)
        .count('* as count')
    ]);
    
    return {
      data,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: parseInt(count),
        pages: Math.ceil(count / limit)
      }
    };
  }
};