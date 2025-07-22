const { db } = require('../config/database');
const fileService = require('../services/fileService');

// Get workouts with pagination and filters
const getWorkouts = async (req, res) => {
  try {
    const { user } = req;
    const { 
      clientId, 
      completed, 
      startDate, 
      endDate, 
      page = 1, 
      limit = 20,
      sortBy = 'scheduled_date',
      sortOrder = 'desc' 
    } = req.query;
    
    let query = db('workouts').select('workouts.*', 'users.name as assigned_by_name');
    
    // Join with users table to get specialist name
    query = query.leftJoin('users', 'workouts.assigned_by', 'users.id');
    
    // Apply filters based on user role
    const userRoles = JSON.parse(user.roles);
    
    if (userRoles.includes('client')) {
      // Clients can only see their own workouts
      query = query.where('workouts.client_id', user.id);
    } else if (clientId) {
      // Specialists/admins can filter by client
      query = query.where('workouts.client_id', clientId);
    } else if (userRoles.includes('specialist') && !userRoles.includes('admin')) {
      // Specialists can only see workouts for their assigned clients
      const clientIds = JSON.parse(user.client_ids || '[]');
      if (clientIds.length > 0) {
        query = query.whereIn('workouts.client_id', clientIds);
      } else {
        // No assigned clients
        return res.json({
          workouts: [],
          pagination: { page: 1, limit, total: 0, pages: 0 }
        });
      }
    }
    
    // Apply additional filters
    if (completed !== undefined) {
      query = query.where('workouts.completed', completed === 'true');
    }
    
    if (startDate) {
      query = query.where('workouts.scheduled_date', '>=', startDate);
    }
    
    if (endDate) {
      query = query.where('workouts.scheduled_date', '<=', endDate);
    }
    
    // Get total count for pagination
    const countQuery = query.clone();
    const [{ count }] = await countQuery.count('* as count');
    
    // Apply pagination
    const offset = (page - 1) * limit;
    const workouts = await query
      .orderBy(sortBy, sortOrder)
      .limit(limit)
      .offset(offset);
    
    // Parse JSON fields and format response
    const formattedWorkouts = workouts.map(workout => ({
      ...workout,
      exercises: JSON.parse(workout.exercises || '[]'),
      template_data: workout.template_data ? JSON.parse(workout.template_data) : null,
      assignedByName: workout.assigned_by_name
    }));
    
    res.json({
      workouts: formattedWorkouts,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: parseInt(count),
        pages: Math.ceil(count / limit)
      }
    });
  } catch (error) {
    console.error('Get workouts error:', error);
    res.status(500).json({ error: 'Failed to fetch workouts' });
  }
};

// Get single workout by ID
const getWorkout = async (req, res) => {
  try {
    const { id } = req.params;
    const { user } = req;
    
    const workout = await db('workouts')
      .select('workouts.*', 'users.name as assigned_by_name', 'clients.name as client_name')
      .leftJoin('users', 'workouts.assigned_by', 'users.id')
      .leftJoin('users as clients', 'workouts.client_id', 'clients.id')
      .where('workouts.id', id)
      .first();
    
    if (!workout) {
      return res.status(404).json({ error: 'Workout not found' });
    }
    
    // Check authorization
    const userRoles = JSON.parse(user.roles);
    if (userRoles.includes('client') && workout.client_id !== user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    if (userRoles.includes('specialist') && !userRoles.includes('admin')) {
      const clientIds = JSON.parse(user.client_ids || '[]');
      if (!clientIds.includes(workout.client_id)) {
        return res.status(403).json({ error: 'Access denied' });
      }
    }
    
    // Format response
    const formattedWorkout = {
      ...workout,
      exercises: JSON.parse(workout.exercises || '[]'),
      template_data: workout.template_data ? JSON.parse(workout.template_data) : null,
      assignedByName: workout.assigned_by_name,
      clientName: workout.client_name
    };
    
    res.json(formattedWorkout);
  } catch (error) {
    console.error('Get workout error:', error);
    res.status(500).json({ error: 'Failed to fetch workout' });
  }
};

// Create new workout
const createWorkout = async (req, res) => {
  const trx = await db.transaction();
  
  try {
    const { user } = req;
    const workoutData = req.body;
    
    // Determine client_id
    let clientId;
    const userRoles = JSON.parse(user.roles);
    
    if (userRoles.includes('client')) {
      clientId = user.id;
    } else {
      clientId = workoutData.clientId;
      if (!clientId) {
        await trx.rollback();
        return res.status(400).json({ error: 'Client ID required' });
      }
      
      // Verify specialist has access to this client
      if (userRoles.includes('specialist') && !userRoles.includes('admin')) {
        const clientIds = JSON.parse(user.client_ids || '[]');
        if (!clientIds.includes(clientId)) {
          await trx.rollback();
          return res.status(403).json({ error: 'You do not have access to this client' });
        }
      }
    }
    
    // Create workout
    const [workout] = await trx('workouts')
      .insert({
        client_id: clientId,
        assigned_by: user.id,
        name: workoutData.name,
        exercises: JSON.stringify(workoutData.exercises || []),
        scheduled_date: workoutData.scheduledDate || new Date(),
        youtube_link: workoutData.youtubeLink,
        notes: workoutData.notes,
        completed: false,
        template_data: workoutData.templateData ? JSON.stringify(workoutData.templateData) : null
      })
      .returning('*');
    
    // If this is from a template, log it
    if (workoutData.templateId) {
      await trx('audit_logs').insert({
        user_id: user.id,
        action: 'create_from_template',
        resource: 'workout',
        resource_id: workout.id.toString(),
        details: `Created workout from template: ${workoutData.templateId}`,
        ip_address: req.ip,
        user_agent: req.get('user-agent'),
        metadata: JSON.stringify({ templateId: workoutData.templateId })
      });
    }
    
    // Send notification to client
    if (clientId !== user.id) {
      const io = req.app.get('io');
      io.to(clientId).emit('new-workout', {
        id: workout.id,
        name: workout.name,
        assignedBy: user.name,
        scheduledDate: workout.scheduled_date
      });
    }
    
    // Log audit
    await trx('audit_logs').insert({
      user_id: user.id,
      action: 'create',
      resource: 'workout',
      resource_id: workout.id.toString(),
      details: `Created workout "${workout.name}" for client ${clientId}`,
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    await trx.commit();
    
    // Format response
    const formattedWorkout = {
      ...workout,
      exercises: JSON.parse(workout.exercises || '[]'),
      template_data: workout.template_data ? JSON.parse(workout.template_data) : null
    };
    
    res.status(201).json({
      workout: formattedWorkout,
      message: 'Workout created successfully'
    });
  } catch (error) {
    await trx.rollback();
    console.error('Create workout error:', error);
    res.status(500).json({ error: 'Failed to create workout' });
  }
};

// Update workout
const updateWorkout = async (req, res) => {
  const trx = await db.transaction();
  
  try {
    const { id } = req.params;
    const { user } = req;
    const updateData = req.body;
    
    // Check if workout exists and user has permission
    const existing = await trx('workouts').where({ id }).first();
    if (!existing) {
      await trx.rollback();
      return res.status(404).json({ error: 'Workout not found' });
    }
    
    // Check authorization
    const userRoles = JSON.parse(user.roles);
    if (userRoles.includes('client') && existing.client_id !== user.id) {
      await trx.rollback();
      return res.status(403).json({ error: 'Access denied' });
    }
    
    if (userRoles.includes('specialist') && !userRoles.includes('admin')) {
      const clientIds = JSON.parse(user.client_ids || '[]');
      if (!clientIds.includes(existing.client_id)) {
        await trx.rollback();
        return res.status(403).json({ error: 'Access denied' });
      }
    }
    
    // Update workout
    const [updated] = await trx('workouts')
      .where({ id })
      .update({
        name: updateData.name || existing.name,
        exercises: updateData.exercises ? JSON.stringify(updateData.exercises) : existing.exercises,
        scheduled_date: updateData.scheduledDate || existing.scheduled_date,
        youtube_link: updateData.youtubeLink !== undefined ? updateData.youtubeLink : existing.youtube_link,
        notes: updateData.notes !== undefined ? updateData.notes : existing.notes,
        updated_at: new Date()
      })
      .returning('*');
    
    // Log audit
    await trx('audit_logs').insert({
      user_id: user.id,
      action: 'update',
      resource: 'workout',
      resource_id: id,
      details: 'Updated workout',
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    await trx.commit();
    
    // Format response
    const formattedWorkout = {
      ...updated,
      exercises: JSON.parse(updated.exercises || '[]')
    };
    
    res.json({
      workout: formattedWorkout,
      message: 'Workout updated successfully'
    });
  } catch (error) {
    await trx.rollback();
    console.error('Update workout error:', error);
    res.status(500).json({ error: 'Failed to update workout' });
  }
};

// Complete workout
const completeWorkout = async (req, res) => {
  const trx = await db.transaction();
  
  try {
    const { id } = req.params;
    const { user } = req;
    const completionData = req.body;
    
    // Get workout
    const workout = await trx('workouts').where({ id }).first();
    if (!workout) {
      await trx.rollback();
      return res.status(404).json({ error: 'Workout not found' });
    }
    
    // Check authorization (only the assigned client can complete)
    if (workout.client_id !== user.id) {
      await trx.rollback();
      return res.status(403).json({ error: 'Only the assigned client can complete this workout' });
    }
    
    if (workout.completed) {
      await trx.rollback();
      return res.status(400).json({ error: 'Workout already completed' });
    }
    
    // Update exercises with actual values
    const existingExercises = JSON.parse(workout.exercises || '[]');
    const updatedExercises = existingExercises.map(exercise => {
      const completedExercise = completionData.exercises?.find(e => e.id === exercise.id);
      if (completedExercise) {
        return {
          ...exercise,
          actualSets: completedExercise.actualSets || exercise.sets,
          actualReps: completedExercise.actualReps || exercise.reps,
          actualWeight: completedExercise.actualWeight || exercise.weight,
          painLevel: completedExercise.painLevel || 0
        };
      }
      return exercise;
    });
    
    // Update workout
    const [completed] = await trx('workouts')
      .where({ id })
      .update({
        exercises: JSON.stringify(updatedExercises),
        completed: true,
        completed_date: new Date(),
        mood_feedback: completionData.moodFeedback,
        duration: completionData.duration,
        calories_burned: completionData.caloriesBurned,
        notes: completionData.notes || workout.notes,
        updated_at: new Date()
      })
      .returning('*');
    
    // Update client analytics
    await updateClientAnalytics(trx, workout.client_id);
    
    // Notify specialist
    if (workout.assigned_by !== user.id) {
      const io = req.app.get('io');
      io.to(workout.assigned_by).emit('workout-completed', {
        workoutId: workout.id,
        workoutName: workout.name,
        clientId: user.id,
        clientName: user.name,
        completedDate: new Date()
      });
    }
    
    // Log audit
    await trx('audit_logs').insert({
      user_id: user.id,
      action: 'complete',
      resource: 'workout',
      resource_id: id,
      details: `Completed workout with mood: ${completionData.moodFeedback || 'N/A'}`,
      ip_address: req.ip,
      user_agent: req.get('user-agent'),
      metadata: JSON.stringify({
        duration: completionData.duration,
        caloriesBurned: completionData.caloriesBurned,
        moodFeedback: completionData.moodFeedback
      })
    });
    
    await trx.commit();
    
    // Format response
    const formattedWorkout = {
      ...completed,
      exercises: JSON.parse(completed.exercises || '[]')
    };
    
    res.json({
      workout: formattedWorkout,
      message: 'Workout completed successfully!'
    });
  } catch (error) {
    await trx.rollback();
    console.error('Complete workout error:', error);
    res.status(500).json({ error: 'Failed to complete workout' });
  }
};

// Delete workout
const deleteWorkout = async (req, res) => {
  const trx = await db.transaction();
  
  try {
    const { id } = req.params;
    const { user } = req;
    
    // Check if workout exists and user has permission
    const existing = await trx('workouts').where({ id }).first();
    if (!existing) {
      await trx.rollback();
      return res.status(404).json({ error: 'Workout not found' });
    }
    
    // Check authorization
    const userRoles = JSON.parse(user.roles);
    
    // Clients cannot delete workouts
    if (userRoles.includes('client') && !userRoles.includes('specialist')) {
      await trx.rollback();
      return res.status(403).json({ error: 'Clients cannot delete workouts' });
    }
    
    // Specialists can only delete workouts they created or for their clients
    if (userRoles.includes('specialist') && !userRoles.includes('admin')) {
      const clientIds = JSON.parse(user.client_ids || '[]');
      if (existing.assigned_by !== user.id && !clientIds.includes(existing.client_id)) {
        await trx.rollback();
        return res.status(403).json({ error: 'Access denied' });
      }
    }
    
    // Delete associated files if any
    if (existing.exercise_image_url) {
      try {
        const key = existing.exercise_image_url.split('/').slice(-2).join('/');
        await fileService.deleteFile(key);
      } catch (error) {
        console.error('Failed to delete exercise image:', error);
      }
    }
    
    // Delete workout
    await trx('workouts').where({ id }).delete();
    
    // Log audit
    await trx('audit_logs').insert({
      user_id: user.id,
      action: 'delete',
      resource: 'workout',
      resource_id: id,
      details: `Deleted workout: ${existing.name}`,
      ip_address: req.ip,
      user_agent: req.get('user-agent')
    });
    
    await trx.commit();
    
    res.json({ message: 'Workout deleted successfully' });
  } catch (error) {
    await trx.rollback();
    console.error('Delete workout error:', error);
    res.status(500).json({ error: 'Failed to delete workout' });
  }
};

// Upload exercise image/video
const uploadExerciseMedia = async (req, res) => {
  try {
    const { id } = req.params;
    const { user } = req;
    
    // Check if workout exists and user has permission
    const workout = await db('workouts').where({ id }).first();
    if (!workout) {
      return res.status(404).json({ error: 'Workout not found' });
    }
    
    // Check authorization
    const userRoles = JSON.parse(user.roles);
    if (userRoles.includes('client') && workout.client_id !== user.id) {
      return res.status(403).json({ error: 'Access denied' });
    }
    
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    
    // Update workout with media URL
    await db('workouts')
      .where({ id })
      .update({
        exercise_image_url: req.file.location,
        updated_at: new Date()
      });
    
    res.json({
      url: req.file.location,
      message: 'Exercise media uploaded successfully'
    });
  } catch (error) {
    console.error('Upload exercise media error:', error);
    res.status(500).json({ error: 'Failed to upload media' });
  }
};

// Get workout templates
const getWorkoutTemplates = async (req, res) => {
  try {
    const { category, search, page = 1, limit = 20 } = req.query;
    
    let query = db('workouts')
      .select('id', 'name', 'exercises', 'template_data', 'created_at')
      .where('template_data', 'IS NOT', null)
      .orderBy('name', 'asc');
    
    // Filter by category if provided
    if (category) {
      query = query.whereRaw("template_data->>'category' = ?", [category]);
    }
    
    // Search by name
    if (search) {
      query = query.where('name', 'ilike', `%${search}%`);
    }
    
    // Pagination
    const offset = (page - 1) * limit;
    const [templates, [{ count }]] = await Promise.all([
      query.clone().limit(limit).offset(offset),
      query.clone().count('* as count')
    ]);
    
    // Format response
    const formattedTemplates = templates.map(template => ({
      id: template.id,
      name: template.name,
      exercises: JSON.parse(template.exercises || '[]'),
      templateData: JSON.parse(template.template_data || '{}'),
      createdAt: template.created_at
    }));
    
    res.json({
      templates: formattedTemplates,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total: parseInt(count),
        pages: Math.ceil(count / limit)
      }
    });
  } catch (error) {
    console.error('Get workout templates error:', error);
    res.status(500).json({ error: 'Failed to fetch workout templates' });
  }
};

// Helper function to update client analytics
const updateClientAnalytics = async (trx, clientId) => {
  try {
    // This would update various analytics metrics
    // For now, just a placeholder
    const completedWorkouts = await trx('workouts')
      .where({ client_id: clientId, completed: true })
      .count('* as count')
      .first();
    
    // You could update a client_analytics table here
    // or trigger other analytics updates
  } catch (error) {
    console.error('Update analytics error:', error);
  }
};

// Get workout statistics
const getWorkoutStats = async (req, res) => {
  try {
    const { user } = req;
    const { clientId, startDate, endDate } = req.query;
    
    let statsQuery = db('workouts');
    
    // Apply filters based on user role
    const userRoles = JSON.parse(user.roles);
    
    if (userRoles.includes('client')) {
      statsQuery = statsQuery.where('client_id', user.id);
    } else if (clientId) {
      statsQuery = statsQuery.where('client_id', clientId);
    }
    
    if (startDate) {
      statsQuery = statsQuery.where('scheduled_date', '>=', startDate);
    }
    
    if (endDate) {
      statsQuery = statsQuery.where('scheduled_date', '<=', endDate);
    }
    
    // Get various statistics
    const [
      totalWorkouts,
      completedWorkouts,
      avgDuration,
      totalCalories,
      moodDistribution
    ] = await Promise.all([
      statsQuery.clone().count('* as count').first(),
      statsQuery.clone().where('completed', true).count('* as count').first(),
      statsQuery.clone().where('completed', true).avg('duration as avg').first(),
      statsQuery.clone().where('completed', true).sum('calories_burned as total').first(),
      statsQuery.clone()
        .where('completed', true)
        .whereNotNull('mood_feedback')
        .select('mood_feedback')
        .count('* as count')
        .groupBy('mood_feedback')
    ]);
    
    // Calculate completion rate
    const completionRate = totalWorkouts.count > 0 
      ? Math.round((completedWorkouts.count / totalWorkouts.count) * 100)
      : 0;
    
    // Format mood distribution
    const moodStats = {
      1: 0, 2: 0, 3: 0, 4: 0, 5: 0
    };
    moodDistribution.forEach(item => {
      moodStats[item.mood_feedback] = parseInt(item.count);
    });
    
    res.json({
      totalWorkouts: parseInt(totalWorkouts.count),
      completedWorkouts: parseInt(completedWorkouts.count),
      completionRate,
      averageDuration: Math.round(avgDuration.avg) || 0,
      totalCaloriesBurned: parseInt(totalCalories.total) || 0,
      moodDistribution: moodStats,
      dateRange: {
        start: startDate || 'all time',
        end: endDate || 'present'
      }
    });
  } catch (error) {
    console.error('Get workout stats error:', error);
    res.status(500).json({ error: 'Failed to fetch workout statistics' });
  }
};

module.exports = {
  getWorkouts,
  getWorkout,
  createWorkout,
  updateWorkout,
  completeWorkout,
  deleteWorkout,
  uploadExerciseMedia,
  getWorkoutTemplates,
  getWorkoutStats
};