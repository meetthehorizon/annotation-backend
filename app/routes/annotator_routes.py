from flask import Blueprint, current_app, jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.models import db, User, USR, Assignment, Segment, Sentence, Chapter, Project
from app.models import LexicalInfo, DependencyInfo, DiscourseCorefInfo, ConstructionInfo, SentenceTypeInfo

annotator_bp = Blueprint("annotator", __name__)

def get_current_annotator():
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()
    if not user or user.role != 'annotator':
        return None
    return user




@annotator_bp.route('/dashboard', methods=['GET'])
@jwt_required()
def annotator_dashboard():
    annotator = get_current_annotator()
    if not annotator:
        return jsonify({"msg": "Annotator access required"}), 403
    
    # Get all assignments for this annotator
    assignments = Assignment.query.filter_by(annotator_id=annotator.id).all()
    
    # Create a dictionary to organize data hierarchically
    projects_dict = {}
    
    for assignment in assignments:
        usr = USR.query.get(assignment.usr_id)
        if not usr:
            continue
            
        segment = Segment.query.get(assignment.segment_id)
        if not segment:
            continue
            
        sentence = Sentence.query.get(segment.sentence_id)
        if not sentence:
            continue
            
        chapter = Chapter.query.get(sentence.chapter_id)
        if not chapter:
            continue
            
        project = Project.query.get(chapter.project_id)
        if not project:
            continue
        
        # Prepare assignment data
        assignment_data = {
            "assignment_id": assignment.id,
            "segment_id": segment.id,
            "segment_text": segment.text,
            "usr_id": usr.id,
            "status": assignment.annotation_status,
            "sentence_type": usr.sentence_type,
            "can_edit_lexical": assignment.assign_lexical,
            "can_edit_dependency": assignment.assign_dependency,
            "can_edit_discourse": assignment.assign_discourse,
            "can_edit_construction": assignment.assign_construction
        }
        
        # Build hierarchical structure
        if project.id not in projects_dict:
            projects_dict[project.id] = {
                "id": project.id,
                "title": project.title,
                "chapters": {}
            }
            
        if chapter.id not in projects_dict[project.id]["chapters"]:
            projects_dict[project.id]["chapters"][chapter.id] = {
                "id": chapter.id,
                "title": chapter.title,
                "assignments": []
            }
            
        projects_dict[project.id]["chapters"][chapter.id]["assignments"].append(assignment_data)
    
    # Convert to list format for easier frontend handling
    projects_list = []
    for project_id, project_data in projects_dict.items():
        chapters_list = []
        for chapter_id, chapter_data in project_data["chapters"].items():
            chapters_list.append({
                "id": chapter_data["id"],
                "title": chapter_data["title"],
                "assignments": chapter_data["assignments"]
            })
        
        projects_list.append({
            "id": project_data["id"],
            "title": project_data["title"],
            "chapters": chapters_list
        })
    
    return jsonify(projects_list)


@annotator_bp.route('/visualize_usr/<int:usr_id>', methods=['GET'])
@jwt_required()
def visualize_usr(usr_id):
    annotator = get_current_annotator()
    if not annotator:
        return jsonify({"msg": "Annotator access required"}), 403
    
    # Verify this USR is assigned to the current annotator
    assignment = Assignment.query.filter_by(
        usr_id=usr_id,
        annotator_id=annotator.id
    ).first()
    
    if not assignment:
        return jsonify({"msg": "USR not assigned to you"}), 403
    
    usr = USR.query.get(usr_id)
    if not usr:
        return jsonify({"msg": "USR not found"}), 404
    
    segment = Segment.query.get(usr.segment_id)
    if not segment:
        return jsonify({"msg": "Segment not found"}), 404
    
    # Generate the USR text in the standard format
    usr_lines = []
    
    # Add segment_id header
    usr_lines.append(f"<segment_id={segment.segment_id}>")
    
    # Add sentence text (commented)
    usr_lines.append(f"#{segment.text}")
    
    # Add lexical info lines
    for li in sorted(usr.lexical_info, key=lambda x: x.index):
        # Ensure all values are strings and handle None values
        line_parts = [
            li.concept or "-",
            str(li.index) if li.index is not None else "-",
            li.semantic_category if li.semantic_category else "-",
            li.morpho_semantic if li.morpho_semantic else "-",
            # Dependency info
            " ".join([f"{di.head_index}:{di.relation}" 
                     for di in sorted(usr.dependency_info, key=lambda x: x.index)
                     if di.index == li.index]) or "-",
            # Discourse/Coref info
            " ".join([f"{dci.head_index}:{dci.relation}" 
                     for dci in sorted(usr.discourse_coref_info, key=lambda x: x.index)
                     if dci.index == li.index]) or "-",
            li.speakers_view if li.speakers_view else "-",
            # Scope (from sentence_type_info)
            usr.sentence_type_info[0].scope if usr.sentence_type_info and usr.sentence_type_info[0].scope else "-",
            # Construction info
            " ".join([f"{ci.cxn_index}:{ci.component_type}" 
                     for ci in sorted(usr.construction_info, key=lambda x: x.index)
                     if ci.index == li.index]) or "-"
        ]
        usr_lines.append("\t".join(line_parts))
    
    # Add sentence type markers if present
    if usr.sentence_type_info and usr.sentence_type_info[0].scope != 'neutral':
        usr_lines.append(f"%{usr.sentence_type_info[0].scope}")
    
    # Close segment_id
    usr_lines.append("</segment_id>")
    
    usr_text = "\n".join(usr_lines)
    
    # Generate the visualization
    try:
        from graphviz import Digraph
        import tempfile
        import os
        
        def generate_visualization(usr_data):
            from graphviz import Digraph

            dot = Digraph(comment='USR Dependency Graph')
            dot.attr(rankdir='TB')  # Top to Bottom layout
            dot.attr('node', shape='box', style='rounded')

            nodes = {}
            hindi_words = {}
            construction_nodes = set()

            for line in usr_data.split('\n'):
                line = line.strip()
                if not line or line.startswith(('#', '<', '%', '//')):
                    if line.startswith('#'):  # Hindi words line
                        # Fix: split Hindi sentence by whitespace instead of tabs
                        hindi_words = {i+1: word for i, word in enumerate(line[1:].strip().split())}
                    continue

                parts = line.split('\t')
                if len(parts) < 9:
                    continue

                node_id = parts[0]
                try:
                    node_index = int(parts[1]) if parts[1] and parts[1] != '-' else 0
                except ValueError:
                    continue

                is_construction = node_id.startswith('[')
                if is_construction:
                    construction_nodes.add(node_index)

                nodes[node_index] = {
                    'id': f"{node_id}_{node_index}",
                    'original_id': node_id,
                    'deps': [],
                    'word': hindi_words.get(node_index, node_id),
                    'is_construction': is_construction
                }

                # Dependency info (column 5)
                if parts[4] != '-':
                    for dep_rel in parts[4].split():
                        if ':' in dep_rel:
                            head, rel = dep_rel.split(':')
                            if head.isdigit() or head == '0':
                                head_node = int(head) if head != '0' else 'ROOT'
                                nodes[node_index]['deps'].append((head_node, rel))

                # Construction info (column 9)
                if parts[8] != '-':
                    for const_rel in parts[8].split():
                        if ':' in const_rel:
                            head, rel = const_rel.split(':')
                            if head.isdigit():
                                nodes[node_index]['deps'].append((int(head), rel))

            clustered_nodes = set()

            # Construction concept clusters
            construction_colors = ['#FFF2CC', '#D5E8D4', '#DAE8FC', '#E1D5E7']
            for color_idx, constr_index in enumerate(construction_nodes):
                related_nodes = {constr_index}
                for idx, node in nodes.items():
                    for (head_idx, _) in node['deps']:
                        if head_idx == constr_index:
                            related_nodes.add(idx)

                box_color = construction_colors[color_idx % len(construction_colors)]
                with dot.subgraph(name=f'cluster_{constr_index}') as c:
                    c.attr(style='filled,rounded,dotted',
                        color='gray50',
                        fillcolor=box_color,
                        label=nodes[constr_index]['original_id'],
                        fontcolor='black',
                        penwidth='2')

                    for node_idx in related_nodes:
                        node = nodes[node_idx]
                        clustered_nodes.add(node_idx)
                        c.node(node['id'], label=f"{node['original_id']}\n{node['word']}")

            # Non-clustered nodes (normal lexical concepts)
            for idx, node in nodes.items():
                if idx not in clustered_nodes and not node['is_construction']:
                    dot.node(node['id'], label=f"{node['original_id']}\n{node['word']}")

            # Draw edges
            for idx, node in nodes.items():
                for (head_idx, rel) in node['deps']:
                    if head_idx == 'ROOT':
                        continue
                    if head_idx in nodes:
                        head_id = nodes[head_idx]['id']
                        dot.edge(head_id, node['id'], label=rel)

            return dot

        
        # Generate the graph
        dot = generate_visualization(usr_text)
        
        # Create a temporary file
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp:
            temp_path = tmp.name
        
        # Render the graph
        dot.render(temp_path.replace('.png', ''), format='png', cleanup=True)
        
        # Read the image data
        with open(temp_path, 'rb') as f:
            image_data = f.read()
        
        # Clean up
        os.unlink(temp_path)
        
        # Return the image
        from flask import make_response
        response = make_response(image_data)
        response.headers.set('Content-Type', 'image/png')
        response.headers.set('Content-Disposition', 'inline', filename=f'usr_{usr_id}.png')
        return response
        
    except Exception as e:
        current_app.logger.error(f"Error generating visualization: {str(e)}")
        return jsonify({"msg": "Error generating visualization", "error": str(e)}), 500
    
    
@annotator_bp.route('/usr/<int:usr_id>', methods=['GET'])
@jwt_required()
def get_assigned_usr(usr_id):
    annotator = get_current_annotator()
    if not annotator:
        return jsonify({"msg": "Annotator access required"}), 403
    
    # Verify this USR is assigned to the current annotator
    assignment = Assignment.query.filter_by(
        usr_id=usr_id,
        annotator_id=annotator.id
    ).first()
    
    if not assignment:
        return jsonify({"msg": "USR not assigned to you"}), 403
    
    usr = USR.query.get(usr_id)
    if not usr:
        return jsonify({"msg": "USR not found"}), 404
    
    segment = Segment.query.get(usr.segment_id)
    if not segment:
        return jsonify({"msg": "Segment not found"}), 404
    
    # Format the USR data for editing
    lexical_info = sorted([{
        'id': li.id,
        'concept': li.concept,
        'index': li.index,
        'semantic_category': li.semantic_category,
        'morpho_semantic': li.morpho_semantic,
        'speakers_view': li.speakers_view
    } for li in usr.lexical_info], key=lambda x: x['index'])
    
    dependency_info = sorted([{
        'id': di.id,
        'concept': di.concept,
        'index': di.index,
        'head_index': di.head_index,
        'relation': di.relation
    } for di in usr.dependency_info], key=lambda x: x['index'])
    
    discourse_coref_info = sorted([{
        'id': dci.id,
        'concept': dci.concept,
        'index': dci.index,
        'head_index': dci.head_index,
        'relation': dci.relation
    } for dci in usr.discourse_coref_info], key=lambda x: x['index'])
    
    construction_info = sorted([{
        'id': ci.id,
        'concept': ci.concept,
        'index': ci.index,
        'cxn_index': ci.cxn_index,
        'component_type': ci.component_type
    } for ci in usr.construction_info], key=lambda x: x['index'])
    
    sentence_type_info = {}
    if usr.sentence_type_info:
        sti = usr.sentence_type_info[0]
        sentence_type_info = {
            'id': sti.id,
            'sentence_type': sti.sentence_type,
            'scope': sti.scope
        }
    
    return jsonify({
        'assignment_id': assignment.id,
        'permissions': {
            'assign_lexical': assignment.assign_lexical,
            'assign_dependency': assignment.assign_dependency,
            'assign_discourse': assignment.assign_discourse,
            'assign_construction': assignment.assign_construction
        },
        'segment': {
            'id': segment.id,
            'text': segment.text,
            'wxtext': segment.wxtext,
            'englishtext': segment.englishtext
        },
        'usr': {
            'id': usr.id,
            'sentence_type': usr.sentence_type,
            'lexical_info': lexical_info if assignment.assign_lexical else [],
            'dependency_info': dependency_info if assignment.assign_dependency else [],
            'discourse_coref_info': discourse_coref_info if assignment.assign_discourse else [],
            'construction_info': construction_info if assignment.assign_construction else [],
            'sentence_type_info': sentence_type_info
        }
    })

@annotator_bp.route('/usr/<int:usr_id>', methods=['PUT'])
@jwt_required()
def update_usr(usr_id):
    annotator = get_current_annotator()
    if not annotator:
        return jsonify({"msg": "Annotator access required"}), 403

    assignment = Assignment.query.filter_by(
        usr_id=usr_id,
        annotator_id=annotator.id
    ).first()
    if not assignment:
        return jsonify({"msg": "USR not assigned to you"}), 403

    data = request.json
    if not data:
        return jsonify({"msg": "No data provided"}), 400

    usr = USR.query.get(usr_id)
    if not usr:
        return jsonify({"msg": "USR not found"}), 404

    try:
        # --- 1️⃣ Update sentence type ---
        if 'sentence_type' in data:
            usr.sentence_type = data['sentence_type']
            if usr.sentence_type_info:
                usr.sentence_type_info[0].sentence_type = data['sentence_type']

        # Get all existing concept IDs from lexical info (which should have all concepts)
        all_concept_ids = {str(li.id) for li in usr.lexical_info}

        # --- 2️⃣ Handle Lexical Info ---
        existing_lex = {str(li.id): li for li in usr.lexical_info}
        payload_lex = {str(item.get('id')): item for item in data.get('lexical_info', [])}

        # Only clear fields if concept exists but not in payload
        for li_id in all_concept_ids:
            if li_id in existing_lex and li_id not in payload_lex:
                existing_lex[li_id].semantic_category = ''
                existing_lex[li_id].morpho_semantic = ''
                existing_lex[li_id].speakers_view = ''

        # Update or create lexical info
        for li_id, item in payload_lex.items():
            if li_id in existing_lex:
                # Update existing
                li = existing_lex[li_id]
                li.concept = item.get('concept', '')
                li.index = int(item.get('index', 0))
                li.semantic_category = item.get('semantic_category', '')
                li.morpho_semantic = item.get('morpho_semantic', '')
                li.speakers_view = item.get('speakers_view', '')
            else:
                # Insert new
                new_li = LexicalInfo(
                    usr_id=usr.id,
                    concept=item.get('concept', ''),
                    index=int(item.get('index', 0)),
                    semantic_category=item.get('semantic_category', ''),
                    morpho_semantic=item.get('morpho_semantic', ''),
                    speakers_view=item.get('speakers_view', '')
                )
                db.session.add(new_li)

        # --- 3️⃣ Dependency Info ---
        existing_dep = {str(di.id): di for di in usr.dependency_info}
        payload_dep = {str(item.get('id')): item for item in data.get('dependency_info', [])}

        # Handle dependency info for all concepts
        for concept_id in all_concept_ids:
            # If concept exists in payload, update/create
            if concept_id in payload_dep:
                item = payload_dep[concept_id]
                if concept_id in existing_dep:
                    # Update existing
                    di = existing_dep[concept_id]
                    di.concept = item.get('concept', '')
                    di.index = int(item.get('index', 0))
                    di.head_index = str(item.get('head_index', ''))
                    di.relation = item.get('relation', '')
                else:
                    # Create new
                    new_di = DependencyInfo(
                        usr_id=usr.id,
                        concept=item.get('concept', ''),
                        index=int(item.get('index', 0)),
                        head_index=str(item.get('head_index', '')),
                        relation=item.get('relation', '')
                    )
                    db.session.add(new_di)
            elif concept_id in existing_dep:
                # Clear fields if concept exists but not in payload
                existing_dep[concept_id].head_index = ''
                existing_dep[concept_id].relation = ''

        # --- 4️⃣ Discourse/Coref Info ---
        existing_disc = {str(dci.id): dci for dci in usr.discourse_coref_info}
        payload_disc = {str(item.get('id')): item for item in data.get('discourse_coref_info', [])}

        # Handle discourse info for all concepts
        for concept_id in all_concept_ids:
            if concept_id in payload_disc:
                item = payload_disc[concept_id]
                if concept_id in existing_disc:
                    # Update existing
                    dci = existing_disc[concept_id]
                    dci.concept = item.get('concept', '')
                    dci.index = int(item.get('index', 0))
                    dci.head_index = str(item.get('head_index', ''))
                    dci.relation = item.get('relation', '')
                else:
                    # Create new
                    new_dci = DiscourseCorefInfo(
                        usr_id=usr.id,
                        concept=item.get('concept', ''),
                        index=int(item.get('index', 0)),
                        head_index=str(item.get('head_index', '')),
                        relation=item.get('relation', '')
                    )
                    db.session.add(new_dci)
            elif concept_id in existing_disc:
                # Clear fields if concept exists but not in payload
                existing_disc[concept_id].head_index = ''
                existing_disc[concept_id].relation = ''

        # --- 5️⃣ Construction Info ---
        existing_const = {str(ci.id): ci for ci in usr.construction_info}
        payload_const = {str(item.get('id')): item for item in data.get('construction_info', [])}

        # Handle construction info for all concepts
        for concept_id in all_concept_ids:
            if concept_id in payload_const:
                item = payload_const[concept_id]
                if concept_id in existing_const:
                    # Update existing
                    ci = existing_const[concept_id]
                    ci.concept = item.get('concept', '')
                    ci.index = int(item.get('index', 0))
                    ci.cxn_index = str(item.get('cxn_index', ''))
                    ci.component_type = item.get('component_type', '')
                else:
                    # Create new
                    new_ci = ConstructionInfo(
                        usr_id=usr.id,
                        concept=item.get('concept', ''),
                        index=int(item.get('index', 0)),
                        cxn_index=str(item.get('cxn_index', '')),
                        component_type=item.get('component_type', '')
                    )
                    db.session.add(new_ci)
            elif concept_id in existing_const:
                # Clear fields if concept exists but not in payload
                existing_const[concept_id].cxn_index = ''
                existing_const[concept_id].component_type = ''

        # --- 6️⃣ Sentence type info ---
        if 'sentence_type_info' in data:
            sti_data = data['sentence_type_info']
            if usr.sentence_type_info:
                sti = usr.sentence_type_info[0]
                sti.scope = sti_data.get('scope', '')
            else:
                new_sti = SentenceTypeInfo(
                    usr_id=usr.id,
                    sentence_type=usr.sentence_type,
                    scope=sti_data.get('scope', '')
                )
                db.session.add(new_sti)

        assignment.annotation_status = 'In Progress'
        db.session.commit()
        return jsonify({"msg": "USR updated successfully"})

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating USR: {str(e)}")
        return jsonify({"msg": "Error updating USR", "error": str(e)}), 500
    
    
@annotator_bp.route('/submit_usr/<int:usr_id>', methods=['POST'])
@jwt_required()
def submit_usr(usr_id):
    annotator = get_current_annotator()
    if not annotator:
        return jsonify({"msg": "Annotator access required"}), 403
    
    # Verify this USR is assigned to the current annotator
    assignment = Assignment.query.filter_by(
        usr_id=usr_id,
        annotator_id=annotator.id
    ).first()
    
    if not assignment:
        return jsonify({"msg": "USR not assigned to you"}), 403
    
    try:
        assignment.annotation_status = 'Submitted for Review'
        db.session.commit()
        return jsonify({"msg": "USR submitted for review"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"msg": "Error submitting USR", "error": str(e)}), 500
    
    
    
# Concept Routes

@annotator_bp.route('/search_concepts', methods=['GET'])
@jwt_required()
def search_concepts():
    annotator = get_current_annotator()
    if not annotator:
        return jsonify({"msg": "Annotator access required"}), 403

    search_term = request.args.get('term', '').strip()
    search_lang = request.args.get('lang', 'hindi').strip().lower()
    exact_match = request.args.get('exact', 'false').lower() == 'true'

    if not search_term or len(search_term) < 2:
        return jsonify({"results": []})

    from app.models import Concept

    # Search in multiple fields with priority
    query = Concept.query.filter(
        db.or_(
            Concept.concept_label.ilike(f'%{search_term}%'),
            Concept.hindi_label.ilike(f'%{search_term}%'),
            Concept.english_label.ilike(f'%{search_term}%')
        )
    ).limit(20)  # Limit results

    concepts = query.all()
    results = [{
        'concept_label': c.concept_label,
        'hindi_label': c.hindi_label,
        'sanskrit_label': c.sanskrit_label,
        'english_label': c.english_label
    } for c in concepts]

    return jsonify({
        'count': len(results),
        'results': results
    })
