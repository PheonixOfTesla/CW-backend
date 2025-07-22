// ecosystem.config.js
module.exports = {
  apps: [{
    name: 'clockwork-backend',
    script: './src/server.js',
    instances: 'max',
    exec_mode: 'cluster',
    autorestart: true,
    watch: false,
    max_memory_restart: '1G',
    env: {
      NODE_ENV: 'production',
      PORT: 3001
    },
    error_file: './logs/pm2-error.log',
    out_file: './logs/pm2-out.log',
    log_file: './logs/pm2-combined.log',
    time: true,
    merge_logs: true,
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
    
    // Graceful shutdown
    kill_timeout: 5000,
    listen_timeout: 3000,
    
    // Monitoring
    min_uptime: '10s',
    max_restarts: 10,
    
    // Advanced features
    post_update: ['npm install'],
    pre_deploy: 'npm test',
  }],

  deploy: {
    production: {
      user: 'deploy',
      host: ['server1.clockwork.com', 'server2.clockwork.com'],
      ref: 'origin/main',
      repo: 'git@github.com:your-org/clockwork-backend.git',
      path: '/var/www/clockwork-backend',
      'pre-deploy': 'npm test',
      'post-deploy': 'npm install && pm2 reload ecosystem.config.js --env production',
      'post-setup': 'npm install'
    },
    staging: {
      user: 'deploy',
      host: 'staging.clockwork.com',
      ref: 'origin/develop',
      repo: 'git@github.com:your-org/clockwork-backend.git',
      path: '/var/www/clockwork-backend-staging',
      'post-deploy': 'npm install && pm2 reload ecosystem.config.js --env staging'
    }
  }
};